/*
 * Copyright © 2021 Google LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors:
 *		Ingvar Stepanyan <me@rreverser.com>
 */

#include <assert.h>
#include <emscripten.h>
#include <emscripten/proxying.h>
#include <emscripten/threading.h>
#include <emscripten/val.h>
#include <pthread.h>
#include <type_traits>
#include <utility>

#include "libusbi.h"

using namespace emscripten;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"
#pragma clang diagnostic ignored "-Wunused-parameter"

// For some reason, unlike EM_JS, needs to be outside namespace.
EM_JS_DEPS(em_promise_then_impl_deps, "$getWasmTableEntry");

namespace {
typedef void (*PromiseCalback)(EM_VAL result, void* arg);

// clang-format off
	EM_JS(EM_VAL, em_promise_catch_impl, (EM_VAL handle), {
		let promise = Emval.toValue(handle);
		promise = promise.then(
			value => ({error : 0, value}),
			error => {
				const ERROR_CODES = {
					// LIBUSB_ERROR_IO
					NetworkError : -1,
					// LIBUSB_ERROR_INVALID_PARAM
					DataError : -2,
					TypeMismatchError : -2,
					IndexSizeError : -2,
					// LIBUSB_ERROR_ACCESS
					SecurityError : -3,
					// LIBUSB_ERROR_NOT_FOUND
					NotFoundError : -5,
					// LIBUSB_ERROR_BUSY
					InvalidStateError : -6,
					// LIBUSB_ERROR_TIMEOUT
					TimeoutError : -7,
					// LIBUSB_ERROR_INTERRUPTED
					AbortError : -10,
					// LIBUSB_ERROR_NOT_SUPPORTED
					NotSupportedError : -12,
				};
				console.error(error);
        let errorCode = -99; // LIBUSB_ERROR_OTHER
				if (error instanceof DOMException)
				{
					errorCode = ERROR_CODES[error.name] ?? errorCode;
				}
				else if ((error instanceof RangeError) || (error instanceof TypeError))
				{
					errorCode = -2; // LIBUSB_ERROR_INVALID_PARAM
				}
				return {error: errorCode, value: undefined};
			}
    );
    return Emval.toHandle(promise);
	});

  EM_JS(EM_VAL, em_promise_then_impl, (EM_VAL handle, PromiseCalback on_fulfilled, void *arg), {
    let promise = Emval.toValue(handle);
    promise = promise.then(result => {
      getWasmTableEntry(on_fulfilled)(Emval.toHandle(result), arg);
    });
    return Emval.toHandle(promise);
  });
// clang-format on

val em_promise_catch(val&& promise) {
  EM_VAL handle = promise.as_handle();
  handle = em_promise_catch_impl(handle);
  return val::take_ownership(handle);
}

template <typename OnFulfilled>
val em_promise_then(val&& promise, OnFulfilled on_fulfilled) {
  return val::take_ownership(em_promise_then_impl(
      promise.as_handle(),
      [](EM_VAL result, void* arg) {
        (*(OnFulfilled*)arg)(val::take_ownership(result));
      },
      &on_fulfilled));
}

// C++ struct representation for {value, error} object from above
// (performs conversion in the constructor).
struct promise_result {
  libusb_error error;
  val value;

  promise_result(val&& result)
      : error(static_cast<libusb_error>(result["error"].as<int>())),
        value(result["value"]) {}

  // C++ counterpart of the promise helper above that takes a promise, catches
  // its error, converts to a libusb status and returns the whole thing as
  // `promise_result` struct for easier handling.
  static promise_result await(val&& promise) {
    promise = em_promise_catch(std::move(promise));
    return {promise.await()};
  }
};

template <typename T>
struct ValPtr {
 public:
  void init_to(T&& value) { new (ptr) val(std::move(value)); }

  T& get() { return *ptr; }
  T take() { return std::move(get()); }

 protected:
  ValPtr(T* ptr) : ptr(ptr) {}

 private:
  T* ptr;
};

struct CachedDevice {
  val device;
  std::vector<std::vector<uint8_t>> configurations;
};

struct WebUsbDevicePtr : ValPtr<CachedDevice> {
 public:
  WebUsbDevicePtr(libusb_device* dev)
      : ValPtr(static_cast<CachedDevice*>(usbi_get_device_priv(dev))) {}
};

val& get_web_usb_device(libusb_device* dev) {
  return WebUsbDevicePtr(dev).get().device;
}

struct WebUsbTransferPtr : ValPtr<val> {
 public:
  WebUsbTransferPtr(usbi_transfer* itransfer)
      : ValPtr(static_cast<val*>(usbi_get_transfer_priv(itransfer))) {}
};

void em_signal_transfer_completion_impl(usbi_transfer* itransfer,
                                        val&& result) {
  WebUsbTransferPtr(itransfer).init_to(std::move(result));
  usbi_signal_transfer_completion(itransfer);
}

// Store the global `navigator.usb` once upon initialisation.
thread_local const val web_usb = val::global("navigator")["usb"];

EM_JS(EM_VAL,
      em_request_descriptor_impl,
      (EM_VAL deviceHandle, uint16_t value, uint16_t maxLength),
      {
        let device = Emval.toValue(deviceHandle);
        let promise = device
                          .controlTransferIn({
                            requestType : 'standard',
                            recipient : 'device',
                            request : /* LIBUSB_REQUEST_GET_DESCRIPTOR */ 6,
                            value,
                            index : 0
                          },
                                             maxLength)
                          .then(result = > new Uint8Array(result.data.buffer));
        return Emval.toHandle(promise);
      });

static inline val em_request_descriptor(val& device,
                                        uint8_t desc_type,
                                        uint8_t desc_index,
                                        uint16_t max_length) {
  return val::take_ownership(
             em_request_descriptor_impl(device.as_handle(),
                                        ((uint16_t)desc_type << 8) | desc_index,
                                        max_length))
      .await();
}

int em_get_device_list(libusb_context* ctx, discovered_devs** devs) {
  // C++ equivalent of `await navigator.usb.getDevices()`.
  // Note: at this point we must already have some devices exposed -
  // caller must have called `await navigator.usb.requestDevice(...)`
  // in response to user interaction before going to LibUSB.
  // Otherwise this list will be empty.
  auto result = promise_result::await(web_usb.call<val>("getDevices"));
  if (result.error) {
    return result.error;
  }
  auto& web_usb_devices = result.value;
  // Iterate over the exposed devices.
  uint8_t devices_num = web_usb_devices["length"].as<uint8_t>();
  for (uint8_t i = 0; i < devices_num; i++) {
    auto web_usb_device = web_usb_devices[i];
    auto vendor_id = web_usb_device["vendorId"].as<uint16_t>();
    auto product_id = web_usb_device["productId"].as<uint16_t>();
    // TODO: this has to be a unique ID for the device in libusb structs.
    // We can't really rely on the index in the list, and otherwise
    // I can't think of a good way to assign permanent IDs to those
    // devices, so here goes best-effort attempt...
    unsigned long session_id = (vendor_id << 16) | product_id;
    // LibUSB uses that ID to check if this device is already in its own
    // list. As long as there are no two instances of same device
    // connected and exposed to the page, we should be fine...
    auto dev = usbi_get_device_by_session_id(ctx, session_id);
    if (dev == NULL) {
      dev = usbi_alloc_device(ctx, session_id);
      if (dev == NULL) {
        usbi_err(ctx, "failed to allocate a new device structure");
        continue;
      }

      web_usb_device.call<val>("open").await();

      val device_descriptor = em_request_descriptor(
          web_usb_device, LIBUSB_DT_DEVICE, 0, LIBUSB_DT_DEVICE_SIZE);
      val(typed_memory_view(LIBUSB_DT_DEVICE_SIZE,
                            (uint8_t*)&dev->device_descriptor))
          .call<void>("set", device_descriptor);

      std::vector<std::vector<uint8_t>> configurations;
      auto configurations_len = dev->device_descriptor.bNumConfigurations;
      configurations.reserve(configurations_len);
      for (uint8_t j = 0; j < configurations_len; j++) {
        auto config_descriptor = em_request_descriptor(
            web_usb_device, LIBUSB_DT_CONFIG, j, UINT16_MAX);
        configurations.push_back(
            convertJSArrayToNumberVector<uint8_t>(config_descriptor));
      }

      web_usb_device.call<val>("close").await();

      if (usbi_sanitize_device(dev) < 0) {
        libusb_unref_device(dev);
        continue;
      }

      WebUsbDevicePtr(dev).init_to(CachedDevice{
          .device = std::move(web_usb_device),
          .configurations = std::move(configurations),
      });
    }
    *devs = discovered_devs_append(*devs, dev);
  }
  return LIBUSB_SUCCESS;
}

int em_open(libusb_device_handle* handle) {
  auto web_usb_device = get_web_usb_device(handle->dev);
  return promise_result::await(web_usb_device.call<val>("open")).error;
}

void em_close(libusb_device_handle* handle) {
  auto web_usb_device = get_web_usb_device(handle->dev);
  // LibUSB API doesn't allow us to handle an error here, but we still need to
  // wait for the promise to make sure that subsequent attempt to reopen the
  // same device doesn't fail with a "device busy" error.
  promise_result::await(web_usb_device.call<val>("close"));
}

int em_get_config_descriptor_impl(CachedDevice& dev,
                                  uint8_t config_id,
                                  void* buf,
                                  size_t len) {
  auto& config = dev.configurations[config_id];
  len = std::min(len, config.size());
  memcpy(buf, config.data(), len);
  return len;
}

int em_get_active_config_descriptor(libusb_device* dev, void* buf, size_t len) {
  auto& cached_device = WebUsbDevicePtr(dev).get();
  auto web_usb_config = cached_device.device["configuration"];
  if (web_usb_config.isNull()) {
    return LIBUSB_ERROR_NOT_FOUND;
  }
  return em_get_config_descriptor_impl(
      cached_device, web_usb_config["configurationValue"].as<uint8_t>(), buf,
      len);
}

int em_get_config_descriptor(libusb_device* dev,
                             uint8_t idx,
                             void* buf,
                             size_t len) {
  auto& cached_device = WebUsbDevicePtr(dev).get();
  return em_get_config_descriptor_impl(cached_device, idx, buf, len);
}

int em_get_configuration(libusb_device_handle* dev_handle, uint8_t* config) {
  auto web_usb_config = get_web_usb_device(dev_handle->dev)["configuration"];
  if (!web_usb_config.isNull()) {
    *config = web_usb_config["configurationValue"].as<uint8_t>();
  }
  return LIBUSB_SUCCESS;
}

int em_set_configuration(libusb_device_handle* handle, int config) {
  return promise_result::await(get_web_usb_device(handle->dev)
                                   .call<val>("selectConfiguration", config))
      .error;
}

int em_claim_interface(libusb_device_handle* handle, uint8_t iface) {
  return promise_result::await(
             get_web_usb_device(handle->dev).call<val>("claimInterface", iface))
      .error;
}

int em_release_interface(libusb_device_handle* handle, uint8_t iface) {
  return promise_result::await(get_web_usb_device(handle->dev)
                                   .call<val>("releaseInterface", iface))
      .error;
}

int em_set_interface_altsetting(libusb_device_handle* handle,
                                uint8_t iface,
                                uint8_t altsetting) {
  return promise_result::await(
             get_web_usb_device(handle->dev)
                 .call<val>("selectAlternateInterface", iface, altsetting))
      .error;
}

int em_clear_halt(libusb_device_handle* handle, unsigned char endpoint) {
  std::string direction = endpoint & LIBUSB_ENDPOINT_IN ? "in" : "out";
  endpoint &= LIBUSB_ENDPOINT_ADDRESS_MASK;

  return promise_result::await(get_web_usb_device(handle->dev)
                                   .call<val>("clearHalt", direction, endpoint))
      .error;
}

int em_reset_device(libusb_device_handle* handle) {
  return promise_result::await(
             get_web_usb_device(handle->dev).call<val>("reset"))
      .error;
}

void em_destroy_device(libusb_device* dev) {
  WebUsbDevicePtr(dev).take();
}

thread_local const val Uint8Array = val::global("Uint8Array");

void em_start_transfer(usbi_transfer* itransfer, val&& promise) {
  promise = em_promise_catch(std::move(promise));
  em_promise_then(std::move(promise), [itransfer](val&& result) {
    em_signal_transfer_completion_impl(itransfer, std::move(result));
  });
}

int em_submit_transfer(usbi_transfer* itransfer) {
  auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);
  auto web_usb_device = get_web_usb_device(transfer->dev_handle->dev);
  switch (transfer->type) {
    case LIBUSB_TRANSFER_TYPE_CONTROL: {
      auto setup = libusb_control_transfer_get_setup(transfer);
      auto web_usb_control_transfer_params = val::object();

      const char* web_usb_request_type = "unknown";
      // See LIBUSB_REQ_TYPE in windows_winusb.h (or docs for `bmRequestType`).
      switch (setup->bmRequestType & (0x03 << 5)) {
        case LIBUSB_REQUEST_TYPE_STANDARD:
          web_usb_request_type = "standard";
          break;
        case LIBUSB_REQUEST_TYPE_CLASS:
          web_usb_request_type = "class";
          break;
        case LIBUSB_REQUEST_TYPE_VENDOR:
          web_usb_request_type = "vendor";
          break;
      }
      web_usb_control_transfer_params.set("requestType", web_usb_request_type);

      const char* recipient = "other";
      switch (setup->bmRequestType & 0x0f) {
        case LIBUSB_RECIPIENT_DEVICE:
          recipient = "device";
          break;
        case LIBUSB_RECIPIENT_INTERFACE:
          recipient = "interface";
          break;
        case LIBUSB_RECIPIENT_ENDPOINT:
          recipient = "endpoint";
          break;
      }
      web_usb_control_transfer_params.set("recipient", recipient);

      web_usb_control_transfer_params.set("request", setup->bRequest);
      web_usb_control_transfer_params.set("value", setup->wValue);
      web_usb_control_transfer_params.set("index", setup->wIndex);

      if (setup->bmRequestType & LIBUSB_ENDPOINT_IN) {
        em_start_transfer(
            itransfer,
            web_usb_device.call<val>("controlTransferIn",
                                     std::move(web_usb_control_transfer_params),
                                     setup->wLength));
      } else {
        auto data =
            val(typed_memory_view(setup->wLength,
                                  libusb_control_transfer_get_data(transfer)))
                .call<val>("slice");
        em_start_transfer(
            itransfer, web_usb_device.call<val>(
                           "controlTransferOut",
                           std::move(web_usb_control_transfer_params), data));
      }

      break;
    }
    case LIBUSB_TRANSFER_TYPE_BULK:
    case LIBUSB_TRANSFER_TYPE_INTERRUPT: {
      auto endpoint = transfer->endpoint & LIBUSB_ENDPOINT_ADDRESS_MASK;

      if (IS_XFERIN(transfer)) {
        em_start_transfer(
            itransfer,
            web_usb_device.call<val>("transferIn", endpoint, transfer->length));
      } else {
        auto data = val(typed_memory_view(transfer->length, transfer->buffer))
                        .call<val>("slice");
        em_start_transfer(
            itransfer, web_usb_device.call<val>("transferOut", endpoint, data));
      }

      break;
    }
    // TODO: add implementation for isochronous transfers too.
    default:
      return LIBUSB_ERROR_NOT_SUPPORTED;
  }
  return LIBUSB_SUCCESS;
}

void em_clear_transfer_priv(usbi_transfer* itransfer) {
  WebUsbTransferPtr(itransfer).take();
}

int em_cancel_transfer(usbi_transfer* itransfer) {
  return LIBUSB_SUCCESS;
}

int em_handle_transfer_completion(usbi_transfer* itransfer) {
  auto transfer = USBI_TRANSFER_TO_LIBUSB_TRANSFER(itransfer);

  // Take ownership of the transfer result, as `em_clear_transfer_priv`
  // is not called automatically for completed transfers and we must
  // free it to avoid leaks.

  auto result_val = WebUsbTransferPtr(itransfer).take();

  if (itransfer->state_flags & USBI_TRANSFER_CANCELLING) {
    return usbi_handle_transfer_cancellation(itransfer);
  }

  libusb_transfer_status status = LIBUSB_TRANSFER_ERROR;

  // We should have a `{value, error}` object by now (see
  // `em_start_transfer_impl` callback).
  promise_result result(std::move(result_val));

  if (!result.error) {
    auto web_usb_transfer_status = result.value["status"].as<std::string>();
    if (web_usb_transfer_status == "ok") {
      status = LIBUSB_TRANSFER_COMPLETED;
    } else if (web_usb_transfer_status == "stall") {
      status = LIBUSB_TRANSFER_STALL;
    } else if (web_usb_transfer_status == "babble") {
      status = LIBUSB_TRANSFER_OVERFLOW;
    }

    int skip;
    unsigned char endpointDir;

    if (transfer->type == LIBUSB_TRANSFER_TYPE_CONTROL) {
      skip = LIBUSB_CONTROL_SETUP_SIZE;
      endpointDir = libusb_control_transfer_get_setup(transfer)->bmRequestType;
    } else {
      skip = 0;
      endpointDir = transfer->endpoint;
    }

    if (endpointDir & LIBUSB_ENDPOINT_IN) {
      auto data = result.value["data"];
      if (!data.isNull()) {
        itransfer->transferred = data["byteLength"].as<int>();
        val(typed_memory_view(transfer->length - skip, transfer->buffer + skip))
            .call<void>("set", Uint8Array.new_(data["buffer"]));
      }
    } else {
      itransfer->transferred = result.value["bytesWritten"].as<int>();
    }
  }

  return usbi_handle_transfer_completion(itransfer, status);
}
}  // namespace
#pragma clang diagnostic pop

static ProxyingQueue queue;

template <typename Fn, Fn fn, typename... Args>
void proxiedVoid(Args... args) {
  if (emscripten_is_main_runtime_thread()) {
    return fn(std::forward<Args>(args)...);
  }
  // TODO: proxy to the thread that initialized libusb instead?
  assert(queue.proxySync(emscripten_main_runtime_thread_id(),
                         [&] { fn(std::forward<Args>(args)...); }));
}

template <typename Fn, Fn fn, typename... Args>
typename std::invoke_result_t<Fn, Args...> proxied(Args... args) {
  std::invoke_result_t<Fn, Args...> result;
  auto func = [](auto result, Args... args) {
    *result = fn(std::forward<Args>(args)...);
  };
  proxiedVoid<decltype(func), func>(&result, std::forward<Args>(args)...);
  return result;
}

#define PROXIED(fn) proxied<decltype(&fn), &fn>

extern "C" const usbi_os_backend usbi_backend = {
    .name = "Emscripten + WebUSB backend",
    .caps = LIBUSB_CAP_HAS_CAPABILITY,
    .get_device_list = PROXIED(em_get_device_list),
    .open = PROXIED(em_open),
    .close = proxiedVoid<decltype(&em_close), &em_close>,
    .get_active_config_descriptor = PROXIED(em_get_active_config_descriptor),
    .get_config_descriptor = PROXIED(em_get_config_descriptor),
    .get_configuration = PROXIED(em_get_configuration),
    .set_configuration = PROXIED(em_set_configuration),
    .claim_interface = PROXIED(em_claim_interface),
    .release_interface = PROXIED(em_release_interface),
    .set_interface_altsetting = PROXIED(em_set_interface_altsetting),
    .clear_halt = PROXIED(em_clear_halt),
    .reset_device = PROXIED(em_reset_device),
    .destroy_device =
        proxiedVoid<decltype(&em_destroy_device), &em_destroy_device>,
    .submit_transfer = PROXIED(em_submit_transfer),
    .cancel_transfer = PROXIED(em_cancel_transfer),
    .clear_transfer_priv =
        proxiedVoid<decltype(&em_clear_transfer_priv), &em_clear_transfer_priv>,
    .handle_transfer_completion = PROXIED(em_handle_transfer_completion),
    .device_priv_size = sizeof(CachedDevice),
    .transfer_priv_size = sizeof(val),
};

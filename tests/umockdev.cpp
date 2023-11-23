/*
 * libusb umockdev based tests
 *
 * Copyright (C) 2022 Benjamin Berg <bberg@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <linux/usbdevice_fs.h>
#include <string.h>
#include <unistd.h>
#include "config.h"

#include <stdarg.h>
#include <deque>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "libusb.h"
#include "libusb_testlib.h"

#include "umockdev-server.h"

/* avoid leak reports inside assertions; leaking stuff on assertion failures
 * does not matter in tests */
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#pragma GCC diagnostic ignored "-Wanalyzer-file-leak"
#endif

struct LogMessage {
	std::thread::id thread;
	libusb_context* ctx;
	enum libusb_log_level level;
	std::string str;
};

template <typename... Args>
std::string string_format(const char* format, Args... args) {
	auto len = std::snprintf(nullptr, 0, format, args...);
	if (len <= 0) {
		throw std::runtime_error("Error during formatting.");
	}
	std::string buf(len, '\0');
	buf.reserve(len + /* extra space for \0 */ 1);
	std::snprintf(buf.data(), buf.capacity(), format, args...);
	return buf;
}

template <typename... Args>
static void throw_error(const char* format, Args... args) {
	throw std::runtime_error(string_format(format, args...));
}

static const std::thread::id main_thread_id = std::this_thread::get_id();

#define assert(cond) \
	if (!(cond))     \
	throw_error("%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond)

#define assert_int_eq(a_, b_)                                         \
	if (int a = (a_), b = (b_); a != b) {                             \
		throw_error("%s:%d: assertion failed: %s == %s (%d == %d)\n", \
					__FILE__, __LINE__, #a_, #b_, a, b);              \
	}

class Mocking {
	MockingFixture* fixture;

public:

	Mocking() : fixture(test_fixture_setup_mocking()) {}
	~Mocking() { test_fixture_teardown_mocking(fixture); }

	void add_canon() { test_fixture_add_canon(fixture); }

	void remove_canon() { test_fixture_remove_canon(fixture); }

	void set_chats(UsbChat* chat, size_t nchats) {
		test_fixture_set_chats(fixture, chat, nchats);
	}

	template <size_t N>
	void set_chats(UsbChat (&chats)[N]) {
		set_chats(&chats, N);
	}
};

class UMockdevTestbedFixture {
	Mocking mocking;

	libusb_context* ctx;

	bool libusb_log_silence = false;
	std::deque<LogMessage> libusb_log;

	std::mutex mutex;

	/* Global for log handler */
	inline static UMockdevTestbedFixture* cur_fixture;

	static void log_handler(libusb_context* ctx,
							enum libusb_log_level level,
							const char* str) {
		assert(cur_fixture);
		auto& fixture = *cur_fixture;
		std::lock_guard<std::mutex> lock(fixture.mutex);

		std::string s = str;
		s.pop_back();  // remove \n

		if (!fixture.libusb_log_silence) {
			fprintf(stderr, "%s\n", s.c_str());
		}

		fixture.libusb_log.emplace_back(LogMessage{
			.thread = std::this_thread::get_id(),
			.ctx = ctx,
			.level = level,
			.str = std::move(s),
		});
	}

	static void log_handler_null(libusb_context* ctx,
								 enum libusb_log_level level,
								 const char* str) {
		(void)ctx;
		(void)level;
		(void)str;
	}

	void clear_libusb_log(enum libusb_log_level level) {
		std::lock_guard<std::mutex> lock(mutex);

		while (!libusb_log.empty()) {
			LogMessage& msg = libusb_log.front();

			assert(msg.ctx == ctx);

			if (msg.level < level) {
				return;
			}

			libusb_log.pop_front();
		}
	}

	void assert_libusb_log_msg(enum libusb_log_level level, const char* re) {
		std::lock_guard<std::mutex> lock(mutex);

		while (!libusb_log.empty()) {
			LogMessage msg = std::move(libusb_log.front());
			libusb_log.pop_front();

			if (msg.ctx != ctx) {
				throw_error(
					"Saw unexpected message \"%s\" from context %p while %p "
					"was expected",
					msg.str.c_str(), msg.ctx, ctx);
			}

			if (msg.level == level &&
				std::regex_search(msg.str, std::regex(re))) {
				return;
			}

			/* Allow skipping INFO and DEBUG messages */
			if (msg.level >= LIBUSB_LOG_LEVEL_INFO)
				continue;

			throw_error("Searched for \"%s\" (%d) but found \"%s\" (%d)", re,
						level, msg.str.c_str(), msg.level);
		}

		throw_error("Searched for \"%s\" (%d) but no message matched", re,
					level);
	}

	void assert_libusb_no_log_msg(enum libusb_log_level level, const char* re) {
		std::lock_guard<std::mutex> lock(mutex);

		while (!libusb_log.empty()) {
			LogMessage msg = std::move(libusb_log.front());
			libusb_log.pop_front();

			assert(msg.ctx == ctx);

			bool matching = (msg.level == level &&
							 std::regex_search(msg.str, std::regex(re)));

			/* Allow skipping INFO and DEBUG messages */
			if (!matching && msg.level >= LIBUSB_LOG_LEVEL_INFO)
				continue;

			throw_error(
				"Asserting \"%s\" (%d) not logged and found \"%s\" (%d)", re,
				level, msg.str.c_str(), msg.level);
		}
	}

	static libusb_context* test_fixture_setup_libusb(ssize_t devcount) {
		libusb_device** devs = NULL;

		libusb_context* ctx = NULL;
		libusb_init_context(/*ctx=*/&ctx, /*options=*/NULL, /*num_options=*/0);

		/* Supress global log messages completely
		 * (though, in some tests it might be interesting to check there are no
		 * real ones).
		 */
		libusb_set_log_cb(NULL, log_handler_null, LIBUSB_LOG_CB_GLOBAL);
		libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG);
		assert_int_eq(libusb_get_device_list(ctx, &devs), devcount);
		libusb_free_device_list(devs, true);
		libusb_set_log_cb(ctx, log_handler, LIBUSB_LOG_CB_CONTEXT);

		return ctx;
	}

	static void transfer_cb_inc_user_data(libusb_transfer* transfer) {
		*(int*)transfer->user_data += 1;
	}

	static constexpr size_t THREADED_SUBMIT_URB_SETS = 64;
	static constexpr size_t THREADED_SUBMIT_URB_IN_FLIGHT = 64;

	struct TestThreadedSubmit {
		libusb_transfer*
			transfers[THREADED_SUBMIT_URB_IN_FLIGHT * THREADED_SUBMIT_URB_SETS];
		int submitted;
		int completed;
		int done;
		UMockdevTestbedFixture* fixture;
	};

	static void transfer_submit_all_retry(TestThreadedSubmit* data) {
		for (auto transfer : data->transfers) {
			while (libusb_submit_transfer(transfer) < 0) {
				data->fixture->assert_libusb_log_msg(LIBUSB_LOG_LEVEL_ERROR,
													 "submit_bulk_transfer");
				continue;
			}

			data->submitted += 1;
		}
	}

	static void test_threaded_submit_transfer_cb(libusb_transfer* transfer) {
		TestThreadedSubmit* data = (TestThreadedSubmit*)transfer->user_data;

		/* We should only be receiving packets in the main thread */
		assert(std::this_thread::get_id() == main_thread_id);

		/* Check that the transfer buffer has the expected value */
		assert_int_eq(*(int*)transfer->buffer, data->completed);
		data->completed += 1;

		if (data->completed == std::size(data->transfers))
			data->done = true;
	}

	static int hotplug_count_arrival_cb(libusb_context* ctx,
										libusb_device* device,
										libusb_hotplug_event event,
										void* user_data) {
		assert_int_eq(event, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);

		(void)ctx;
		(void)device;

		*(int*)user_data += 1;

		return 0;
	}

#ifdef UMOCKDEV_HOTPLUG
	static int hotplug_count_removal_cb(libusb_context* ctx,
										libusb_device* device,
										libusb_hotplug_event event,
										void* user_data) {
		assert_int_eq(event, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT);

		(void)ctx;
		(void)device;

		*(int*)user_data += 1;

		return 0;
	}
#endif

public:

	UMockdevTestbedFixture(bool with_canon) {
		if (with_canon) {
			mocking.add_canon();
		}
		ctx = test_fixture_setup_libusb(with_canon ? 1 : 0);
	}

	// Make sure it's immovable because we store its address in `cur_fixture`.
	UMockdevTestbedFixture(UMockdevTestbedFixture&&) = delete;

	~UMockdevTestbedFixture() {
		/* Abort if there are any warnings/errors in the log */
		clear_libusb_log(LIBUSB_LOG_LEVEL_INFO);

		if (ctx) {
			libusb_device** devs = NULL;
			int count = libusb_get_device_list(ctx, &devs);
			libusb_free_device_list(devs, true);

			libusb_exit(ctx);

			/* libusb_exit should result in the correct number of devices being
			 * destroyed */
			for (int i = 0; i < count; i++)
				assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
									  "libusb_unref_device");

			assert_libusb_no_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
									 "libusb_unref_device");
		}
		libusb_set_log_cb(NULL, NULL, LIBUSB_LOG_CB_GLOBAL);

		/* Abort if there are any warnings/errors in the log */
		clear_libusb_log(LIBUSB_LOG_LEVEL_INFO);
		ctx = NULL;
		assert(libusb_log.empty());
	}

	template <bool with_canon, void (UMockdevTestbedFixture::*test_method)()>
	static libusb_testlib_result run_test() {
		libusb_testlib_result result = TEST_STATUS_SUCCESS;
		try {
			UMockdevTestbedFixture fixture(with_canon);
			assert(!cur_fixture);
			cur_fixture = &fixture;
			(fixture.*test_method)();
		} catch (const std::exception& e) {
			libusb_testlib_logf("%s", e.what());
			result = TEST_STATUS_FAILURE;
		}
		cur_fixture = NULL;
		return result;
	}

	void test_open_close() {
		libusb_device** devs = NULL;
		libusb_device_descriptor desc;
		libusb_device_handle* handle = NULL;

		assert_int_eq(libusb_get_device_list(ctx, &devs), 1);
		/* The linux_enumerate_device may happen from a different thread */
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG, "libusb_get_device_list");
		/* We have exactly one device */
		assert_int_eq(libusb_get_bus_number(devs[0]), 1);
		assert_int_eq(libusb_get_device_address(devs[0]), 1);

		/* Get/Check descriptor */
		clear_libusb_log(LIBUSB_LOG_LEVEL_INFO);
		libusb_get_device_descriptor(devs[0], &desc);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
							  "libusb_get_device_descriptor");
		assert_int_eq(desc.idVendor, 0x04a9);
		assert_int_eq(desc.idProduct, 0x31c0);

		/* Open and close */
		assert_int_eq(libusb_open(devs[0], &handle), 0);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG, "usbi_add_event_source");
		assert(handle);
		libusb_close(handle);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
							  "usbi_remove_event_source");

		libusb_free_device_list(devs, true);

		/* Open and close using vid/pid */
		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);
		libusb_close(handle);
	}

	void test_implicit_default() {
		libusb_device** devs = NULL;

		clear_libusb_log(LIBUSB_LOG_LEVEL_INFO);
		assert_int_eq(libusb_get_device_list(NULL, &devs), 1);
		libusb_free_device_list(devs, true);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_ERROR,
							  "\\[usbi_get_context\\].*implicit default");

		/* Only warns once */
		assert_int_eq(libusb_get_device_list(NULL, &devs), 1);
		libusb_free_device_list(devs, true);
		clear_libusb_log(LIBUSB_LOG_LEVEL_INFO);

		libusb_init_context(/*ctx=*/NULL, /*options=*/NULL, /*num_options=*/0);
		assert_int_eq(libusb_get_device_list(NULL, &devs), 1);
		libusb_exit(NULL);

		/* We free late, causing a warning from libusb_exit. However,
		 * we never see this warning (i.e. test success) because it is on a
		 * different context.
		 */
		libusb_free_device_list(devs, true);
	}

	void test_close_flying() {
		UsbChat chat[] = {
			{
				.submit = true,
				.type = USBDEVFS_URB_TYPE_BULK,
				.endpoint = LIBUSB_ENDPOINT_OUT,
				.buffer = (const unsigned char[]){0x01, 0x02, 0x03, 0x04},
				.buffer_length = 4,
			},
			{.submit = false}};
		libusb_device_handle* handle = NULL;
		libusb_transfer* transfer = NULL;

		mocking.set_chats(chat);

		/* Open */
		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		transfer = libusb_alloc_transfer(0);
		// Note: don't reuse `chat[0].buffer` because it might be modified.
		libusb_fill_bulk_transfer(
			transfer, handle, LIBUSB_ENDPOINT_OUT,
			(unsigned char[]){0x01, 0x02, 0x03, 0x04}, 4, NULL, NULL, 1);

		/* Submit */
		libusb_submit_transfer(transfer);

		/* Closing logs fat error (two lines) */
		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);
		libusb_close(handle);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_ERROR,
							  "\\[do_close\\] .*connected as far as we know");
		assert_libusb_log_msg(
			LIBUSB_LOG_LEVEL_ERROR,
			"\\[do_close\\] .*cancellation hasn't even been scheduled");
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
							  "\\[do_close\\] Removed transfer");

		/* Free'ing the transfer works, and logs to the right context */
		libusb_free_transfer(transfer);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
							  "\\[libusb_free_transfer\\]");
	}

	void test_close_cancelled() {
		UsbChat chat[] = {
			{
				.submit = true,
				.type = USBDEVFS_URB_TYPE_BULK,
				.endpoint = LIBUSB_ENDPOINT_OUT,
				.buffer = (const unsigned char[]){0x01, 0x02, 0x03, 0x04},
				.buffer_length = 4,
			},
			{.submit = false}};
		libusb_device_handle* handle = NULL;
		libusb_transfer* transfer = NULL;

		mocking.set_chats(chat);

		/* Open */
		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		transfer = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(transfer, handle, LIBUSB_ENDPOINT_OUT,
								  (unsigned char*)chat[0].buffer,
								  chat[0].buffer_length, NULL, NULL, 1);

		/* Submit */
		libusb_submit_transfer(transfer);
		libusb_cancel_transfer(transfer);

		/* Closing logs fat error (two lines) */
		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);
		libusb_close(handle);
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_ERROR,
							  "\\[do_close\\] .*connected as far as we know");
		assert_libusb_log_msg(
			LIBUSB_LOG_LEVEL_WARNING,
			"\\[do_close\\] .*cancellation.*hasn't completed");
		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_DEBUG,
							  "\\[do_close\\] Removed transfer");

		libusb_free_transfer(transfer);
	}

	void test_ctx_destroy() {
		UsbChat chat[] = {
			{
				.submit = true,
				.type = USBDEVFS_URB_TYPE_BULK,
				.endpoint = LIBUSB_ENDPOINT_OUT,
				.buffer = (const unsigned char[]){0x01, 0x02, 0x03, 0x04},
				.buffer_length = 4,
			},
			{.submit = false}};
		libusb_device_handle* handle = NULL;
		libusb_transfer* transfer = NULL;

		mocking.set_chats(chat);

		/* Open */
		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		transfer = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(transfer, handle, LIBUSB_ENDPOINT_OUT,
								  (unsigned char*)chat[0].buffer,
								  chat[0].buffer_length, NULL, NULL, 1);

		/* Submit */
		libusb_submit_transfer(transfer);

		/* Now we are evil and destroy the ctx! */
		libusb_exit(ctx);

		assert_libusb_log_msg(LIBUSB_LOG_LEVEL_WARNING,
							  "\\[libusb_exit\\] device.*still referenced");
		assert_libusb_log_msg(
			LIBUSB_LOG_LEVEL_WARNING,
			"\\[libusb_exit\\] application left some devices open");

		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);
		ctx = NULL;

		/* XXX: Closing crashes the application as it unref's the NULL pointer
		 */
		/* libusb_close(handle); */

		libusb_free_transfer(transfer);
	}

	void test_get_string_descriptor() {
		unsigned char data[255] = {
			0,
		};
		libusb_device_handle* handle = NULL;
		UsbChat chat[] = {
			{
				.submit = true,
				.reaps_offset = 1,
				.type = USBDEVFS_URB_TYPE_CONTROL,
				.buffer =
					(const unsigned char*)"\x80\x06\x00\x03\x00\x00\x04\x00",
				.buffer_length = 12, /* 8 byte out*/
			},
			{
				/* String with content 0x0409 (en_US) */
				.buffer = (const unsigned char*)"\x80\x06\x00\x03\x00\x00\x04"
												"\x00\x04\x03\x09\x04",
				.actual_length = 12,
			},
			{
				.submit = true,
				.reaps_offset = 1,
				.type = USBDEVFS_URB_TYPE_CONTROL,
				.buffer =
					(const unsigned char*)"\x80\x06\x01\x03\x09\x04\xff\x00",
				.buffer_length = 263, /* 8 byte out*/
			},
			{
				/* 4 byte string, "ab" */
				.buffer = (const unsigned char*)"\x80\x06\x01\x03\x09\x04\xff"
												"\x00\x06\x03\x61\x00\x62\x00",
				.actual_length = 14,
			},
			{
				.submit = true,
				.reaps_offset = 1,
				.type = USBDEVFS_URB_TYPE_CONTROL,
				.buffer =
					(const unsigned char*)"\x80\x06\x00\x03\x00\x00\x04\x00",
				.buffer_length = 12, /* 8 byte out*/
			},
			{
				.status = -ENOENT,
			},
			{
				.submit = true,
				.type = USBDEVFS_URB_TYPE_CONTROL,
				.status = -ENOENT,
				.buffer =
					(const unsigned char*)"\x80\x06\x00\x03\x00\x00\x04\x00",
				.buffer_length = 12, /* 8 byte out*/
			},
			{
				.submit = false,
			}};

		mocking.set_chats(chat);

		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		/* The chat allows us to fetch the descriptor */
		assert_int_eq(
			libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)),
			2);
		assert_int_eq(memcmp(data, "ab", 2), 0);
		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);

		/* Again, but the URB fails with ENOENT when reaping */
		assert_int_eq(
			libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)),
			-1);
		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);

		/* Again, but the URB fails to submit with ENOENT */
		assert_int_eq(
			libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)),
			-1);
		assert_libusb_log_msg(
			LIBUSB_LOG_LEVEL_ERROR,
			"\\[submit_control_transfer\\] submiturb failed, errno=2");
		clear_libusb_log(LIBUSB_LOG_LEVEL_DEBUG);

		libusb_close(handle);
	}

	void test_timeout() {
		UsbChat chat[] = {
			{
				.submit = true,
				.type = USBDEVFS_URB_TYPE_BULK,
				.endpoint = LIBUSB_ENDPOINT_OUT,
				.buffer = (const unsigned char[]){0x01, 0x02, 0x03, 0x04},
				.buffer_length = 4,
			},
			{
				.submit = false,
			}};
		int completed = 0;
		libusb_device_handle* handle = NULL;
		libusb_transfer* transfer = NULL;

		mocking.set_chats(chat);

		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		transfer = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(transfer, handle, LIBUSB_ENDPOINT_OUT,
								  (unsigned char*)chat[0].buffer,
								  chat[0].buffer_length,
								  transfer_cb_inc_user_data, &completed, 10);

		libusb_submit_transfer(transfer);
		while (!completed) {
			assert_int_eq(libusb_handle_events_completed(ctx, &completed), 0);
			/* Silence after one iteration. */
			libusb_log_silence = true;
		}
		libusb_log_silence = false;

		assert_int_eq(transfer->status, LIBUSB_TRANSFER_TIMED_OUT);
		libusb_free_transfer(transfer);

		libusb_close(handle);
	}

	void test_threaded_submit() {
		libusb_log_silence = true;

		TestThreadedSubmit data = {.fixture = this};
		UsbChat out_msg = {
			.submit = true,
			.type = USBDEVFS_URB_TYPE_BULK,
			.endpoint = LIBUSB_ENDPOINT_IN,
			.buffer_length = sizeof(int),
		};
		UsbChat in_msg = {
			.actual_length = 4,
		};
		libusb_device_handle* handle = NULL;
		int urb;

		handle = libusb_open_device_with_vid_pid(ctx, 0x04a9, 0x31c0);
		assert(handle);

		std::vector<UsbChat> c(std::size(data.transfers) * 2 + 1);

		std::vector<int> urbs(std::size(data.transfers) * 2);
		for (int i = 0; i < std::size(urbs); i++) {
			urbs[i] = i;
		}

		urb = 0;
		for (int i = 0; i < THREADED_SUBMIT_URB_SETS; i++) {
			for (int j = 0; j < THREADED_SUBMIT_URB_IN_FLIGHT; j++) {
				c[i * 2 * THREADED_SUBMIT_URB_IN_FLIGHT + j] = out_msg;
				c[i * 2 * THREADED_SUBMIT_URB_IN_FLIGHT + j].reaps_offset =
					THREADED_SUBMIT_URB_IN_FLIGHT;
				c[(i * 2 + 1) * THREADED_SUBMIT_URB_IN_FLIGHT + j] = in_msg;
				c[(i * 2 + 1) * THREADED_SUBMIT_URB_IN_FLIGHT + j].buffer =
					(const unsigned char*)&urbs[urb];

				data.transfers[urb] = libusb_alloc_transfer(0);
				libusb_fill_bulk_transfer(
					data.transfers[urb], handle, LIBUSB_ENDPOINT_IN,
					(unsigned char*)malloc(out_msg.buffer_length),
					out_msg.buffer_length, test_threaded_submit_transfer_cb,
					&data, UINT_MAX);
				data.transfers[urb]->flags =
					LIBUSB_TRANSFER_FREE_BUFFER | LIBUSB_TRANSFER_FREE_TRANSFER;
				urb++;
			}
		}

		mocking.set_chats(c.data(), c.size());

		std::thread thread(transfer_submit_all_retry, &data);

		while (!data.done)
			assert_int_eq(libusb_handle_events_completed(ctx, &data.done), 0);

		thread.join();

		libusb_log_silence = false;
		libusb_close(handle);
	}

	void test_hotplug_enumerate() {
		libusb_hotplug_callback_handle handle_enumerate;
		libusb_hotplug_callback_handle handle_no_enumerate;
		int event_count_enumerate = 0;
		int event_count_no_enumerate = 0;
		struct timeval zero_tv = {0};
		int r;

		printf("Registering callback 1\n");

		r = libusb_hotplug_register_callback(
			ctx,
			LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
				LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
			LIBUSB_HOTPLUG_ENUMERATE, LIBUSB_HOTPLUG_MATCH_ANY,
			LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
			hotplug_count_arrival_cb, &event_count_enumerate,
			&handle_enumerate);
		assert_int_eq(r, 0);

		printf("Registering callback 2\n");

		r = libusb_hotplug_register_callback(
			ctx,
			LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
				LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
			0, LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
			LIBUSB_HOTPLUG_MATCH_ANY, hotplug_count_arrival_cb,
			&event_count_no_enumerate, &handle_no_enumerate);
		assert_int_eq(r, 0);

		assert_int_eq(event_count_enumerate, 1);
		assert_int_eq(event_count_no_enumerate, 0);

		printf("Handling events\n");

		libusb_handle_events_timeout(ctx, &zero_tv);

		assert_int_eq(event_count_enumerate, 1);
		assert_int_eq(event_count_no_enumerate, 0);

		libusb_hotplug_deregister_callback(ctx, handle_enumerate);
		libusb_hotplug_deregister_callback(ctx, handle_no_enumerate);

		libusb_handle_events_timeout(ctx, &zero_tv);

		assert_int_eq(event_count_enumerate, 1);
		assert_int_eq(event_count_no_enumerate, 0);
	}

	void test_hotplug_add_remove() {
#ifdef UMOCKDEV_HOTPLUG
		libusb_device** devs = NULL;
		libusb_hotplug_callback_handle handle_add;
		libusb_hotplug_callback_handle handle_remove;
		int event_count_add = 0;
		int event_count_remove = 0;
		struct timeval zero_tv = {0};
		int r;

		r = libusb_hotplug_register_callback(
			ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, LIBUSB_HOTPLUG_ENUMERATE,
			LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
			LIBUSB_HOTPLUG_MATCH_ANY, hotplug_count_arrival_cb,
			&event_count_add, &handle_add);
		assert_int_eq(r, 0);

		r = libusb_hotplug_register_callback(
			ctx, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, LIBUSB_HOTPLUG_ENUMERATE,
			LIBUSB_HOTPLUG_MATCH_ANY, LIBUSB_HOTPLUG_MATCH_ANY,
			LIBUSB_HOTPLUG_MATCH_ANY, hotplug_count_removal_cb,
			&event_count_remove, &handle_remove);
		assert_int_eq(r, 0);

		/* No device, even going into the mainloop will not call cb. */
		libusb_handle_events_timeout(ctx, &zero_tv);
		assert_int_eq(event_count_add, 0);
		assert_int_eq(event_count_remove, 0);

		/* Add a device */
		mocking.add_canon();

		/* Either the thread has picked it up already, or we do so now. */
		assert_int_eq(libusb_get_device_list(ctx, &devs), 1);
		libusb_free_device_list(devs, true);

		/* The hotplug event is pending now, but has not yet fired. */
		assert_int_eq(event_count_add, 0);
		assert_int_eq(event_count_remove, 0);

		/* Fire hotplug event. */
		libusb_handle_events_timeout(ctx, &zero_tv);
		assert_int_eq(event_count_add, 1);
		assert_int_eq(event_count_remove, 0);

		// TODO: uncomment this: umockdev_testbed_uevent(testbed,
		// "/sys/devices/usb1", "remove");
		// umockdev_testbed_remove_device(testbed, "/devices/usb1");
		mocking.remove_canon();

		/* Either the thread has picked it up already, or we do so now. */
		assert_int_eq(libusb_get_device_list(ctx, &devs), 0);
		libusb_free_device_list(devs, true);

		/* The hotplug event is pending now, but has not yet fired. */
		assert_int_eq(event_count_add, 1);
		assert_int_eq(event_count_remove, 0);

		/* Fire hotplug event. */
		libusb_handle_events_timeout(ctx, &zero_tv);
		assert_int_eq(event_count_add, 1);
		assert_int_eq(event_count_remove, 1);

		libusb_hotplug_deregister_callback(ctx, handle_add);
		libusb_hotplug_deregister_callback(ctx, handle_remove);
#else
		(void)fixture;
		libusb_testlib_logf(
			"Skipping hotplug test, UMockdev is too old to test hotplug");
#endif
	}
};

#define WRAP_TEST(WITH_CANON, METHOD)                                         \
	{                                                                         \
		#METHOD,                                                              \
			UMockdevTestbedFixture::run_test<WITH_CANON,                      \
											 &UMockdevTestbedFixture::METHOD> \
	}

static constexpr libusb_testlib_test tests[] = {
	WRAP_TEST(true, test_open_close),
	WRAP_TEST(true, test_implicit_default),

	WRAP_TEST(true, test_close_flying),
	WRAP_TEST(true, test_close_cancelled),

	WRAP_TEST(true, test_ctx_destroy),
	WRAP_TEST(true, test_get_string_descriptor),
	WRAP_TEST(true, test_timeout),
	WRAP_TEST(true, test_threaded_submit),
	WRAP_TEST(true, test_hotplug_enumerate),

	WRAP_TEST(false, test_hotplug_add_remove),

	LIBUSB_NULL_TEST};

int main(int argc, char** argv) {
	return libusb_testlib_run_tests(argc, argv, tests);
}

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

#include "config.h"
#include <glib.h>
#include <glib/gstdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/usbdevice_fs.h>

#include "libusb.h"

#include "umockdev-server.h"

#define UNUSED_DATA __attribute__ ((unused)) gconstpointer unused_data

/* avoid leak reports inside assertions; leaking stuff on assertion failures does not matter in tests */
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#pragma GCC diagnostic ignored "-Wanalyzer-file-leak"
#endif

typedef struct {
	pid_t thread;
	libusb_context *ctx;
	enum libusb_log_level level;
	char *str;
} LogMessage;

static void
log_message_free(LogMessage *msg)
{
	g_free(msg->str);
	g_free(msg);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(LogMessage, log_message_free)

typedef struct _MockingFixture MockingFixture;

typedef struct {
	struct libusb_context *ctx;

	gboolean libusb_log_silence;
	GList *libusb_log;

	/* GMutex confuses tsan unecessarily */
	pthread_mutex_t mutex;

	MockingFixture *mocking;
} UMockdevTestbedFixture;

/* Global for log handler */
static UMockdevTestbedFixture *cur_fixture = NULL;

static void
log_handler(libusb_context *ctx, enum libusb_log_level level, const char *str)
{
	/* May be called from different threads without synchronization! */
	LogMessage *msg;
	pid_t tid = gettid();

	g_assert (cur_fixture != NULL);
	g_assert(pthread_mutex_lock(&cur_fixture->mutex) == 0);

	msg = g_new0(LogMessage, 1);
	msg->ctx = ctx;
	msg->level = level;
	msg->str = g_strchomp (g_strdup(str));
	msg->thread = tid;

	if (!cur_fixture->libusb_log_silence)
		g_printerr("%s\n", msg->str);

	cur_fixture->libusb_log = g_list_append(cur_fixture->libusb_log, msg);
	pthread_mutex_unlock(&cur_fixture->mutex);
}

static void
log_handler_null(libusb_context *ctx, enum libusb_log_level level, const char *str)
{
	(void) ctx;
	(void) level;
	(void) str;
}

static void
clear_libusb_log(UMockdevTestbedFixture * fixture, enum libusb_log_level level)
{
	g_assert(pthread_mutex_lock(&fixture->mutex) == 0);

	while (fixture->libusb_log) {
		LogMessage *msg = fixture->libusb_log->data;

		g_assert(msg->ctx == fixture->ctx);

		if (msg->level < level) {
			pthread_mutex_unlock(&fixture->mutex);
			return;
		}

		fixture->libusb_log = g_list_delete_link(fixture->libusb_log, fixture->libusb_log);
		log_message_free(msg);
	}
	pthread_mutex_unlock(&fixture->mutex);
}

static void
assert_libusb_log_msg(UMockdevTestbedFixture * fixture, enum libusb_log_level level, const char *re)
{
	g_assert(pthread_mutex_lock(&fixture->mutex) == 0);

	while (fixture->libusb_log) {
		g_autoptr(LogMessage) msg = NULL;

		if (fixture->libusb_log == NULL)
			g_error ("No level %d message found searching for %s", level, re);

		msg = fixture->libusb_log->data;
		fixture->libusb_log = g_list_delete_link(fixture->libusb_log, fixture->libusb_log);

		if (msg->ctx != fixture->ctx)
			g_error ("Saw unexpected message \"%s\" from context %p while %p was expected",
				 msg->str, msg->ctx, fixture->ctx);

		if (msg->level == level && g_regex_match_simple(re, msg->str, 0, 0)) {
			pthread_mutex_unlock(&fixture->mutex);
			return;
		}

		/* Allow skipping INFO and DEBUG messages */
		if (msg->level >= LIBUSB_LOG_LEVEL_INFO)
			continue;

		g_error ("Searched for \"%s\" (%d) but found \"%s\" (%d)", re, level, msg->str, msg->level);
	}

	pthread_mutex_unlock(&fixture->mutex);
	g_error ("Searched for \"%s\" (%d) but no message matched", re, level);
}

static void
assert_libusb_no_log_msg(UMockdevTestbedFixture * fixture, enum libusb_log_level level, const char *re)
{
	g_assert(pthread_mutex_lock(&fixture->mutex) == 0);

	while (fixture->libusb_log) {
		g_autoptr(LogMessage) msg = NULL;
		gboolean matching;

		msg = fixture->libusb_log->data;
		fixture->libusb_log = g_list_delete_link(fixture->libusb_log, fixture->libusb_log);

		g_assert(msg->ctx == fixture->ctx);

		matching = (msg->level == level && g_regex_match_simple(re, msg->str, 0, 0));

		/* Allow skipping INFO and DEBUG messages */
		if (!matching && msg->level >= LIBUSB_LOG_LEVEL_INFO)
			continue;

		g_error ("Asserting \"%s\" (%d) not logged and found \"%s\" (%d)", re, level, msg->str, msg->level);
	}

	pthread_mutex_unlock(&fixture->mutex);
}

static void
test_fixture_setup_libusb(UMockdevTestbedFixture * fixture, int devcount)
{
	libusb_device **devs = NULL;

	libusb_init_context(/*ctx=*/&fixture->ctx, /*options=*/NULL, /*num_options=*/0);

	/* Supress global log messages completely
	 * (though, in some tests it might be interesting to check there are no real ones).
	 */
	libusb_set_log_cb (NULL, log_handler_null, LIBUSB_LOG_CB_GLOBAL);
	libusb_set_option (fixture->ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG);
	g_assert_cmpint(libusb_get_device_list(fixture->ctx, &devs), ==, devcount);
	libusb_free_device_list(devs, TRUE);
	libusb_set_log_cb (fixture->ctx, log_handler, LIBUSB_LOG_CB_CONTEXT);
}

static void
test_fixture_setup_common(UMockdevTestbedFixture * fixture) {
	g_assert(cur_fixture == NULL);
	cur_fixture = fixture;

	pthread_mutex_init(&fixture->mutex, NULL);

	fixture->mocking = test_fixture_setup_mocking();
}

static void
test_fixture_setup_empty(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	test_fixture_setup_common(fixture);

	test_fixture_setup_libusb(fixture, 0);
}

static void
test_fixture_setup_with_canon(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	test_fixture_setup_common(fixture);

	test_fixture_add_canon(fixture->mocking);

	test_fixture_setup_libusb(fixture, 1);
}

static void
test_fixture_teardown(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	g_assert(cur_fixture == fixture);

	/* Abort if there are any warnings/errors in the log */
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_INFO);

	if (fixture->ctx) {
		libusb_device **devs = NULL;
		int count = libusb_get_device_list(fixture->ctx, &devs);
		libusb_free_device_list(devs, TRUE);

		libusb_exit (fixture->ctx);

		/* libusb_exit should result in the correct number of devices being destroyed */
		for (int i = 0; i < count; i++)
			assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "libusb_unref_device");

		assert_libusb_no_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "libusb_unref_device");
	}
	libusb_set_log_cb (NULL, NULL, LIBUSB_LOG_CB_GLOBAL);
	cur_fixture = NULL;

	/* Abort if there are any warnings/errors in the log */
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_INFO);
	fixture->ctx = NULL;
	g_assert_null(fixture->libusb_log);

	test_fixture_teardown_mocking(fixture->mocking);

	pthread_mutex_destroy(&fixture->mutex);
}

static void
test_open_close(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	libusb_device **devs = NULL;
	struct libusb_device_descriptor desc;
	libusb_device_handle *handle = NULL;

	g_assert_cmpint(libusb_get_device_list(fixture->ctx, &devs), ==, 1);
	/* The linux_enumerate_device may happen from a different thread */
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "libusb_get_device_list");
	/* We have exactly one device */
	g_assert_cmpint(libusb_get_bus_number(devs[0]), ==, 1);
	g_assert_cmpint(libusb_get_device_address(devs[0]), ==, 1);

	/* Get/Check descriptor */
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_INFO);
	libusb_get_device_descriptor (devs[0], &desc);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "libusb_get_device_descriptor");
	g_assert_cmpint(desc.idVendor, ==, 0x04a9);
	g_assert_cmpint(desc.idProduct, ==, 0x31c0);

	/* Open and close */
	g_assert_cmpint(libusb_open(devs[0], &handle), ==, 0);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "usbi_add_event_source");
	g_assert_nonnull(handle);
	libusb_close(handle);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "usbi_remove_event_source");

	libusb_free_device_list(devs, TRUE);

	/* Open and close using vid/pid */
	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);
	libusb_close(handle);
}

static void
test_implicit_default(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	libusb_device **devs = NULL;

	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_INFO);
	g_assert_cmpint(libusb_get_device_list(NULL, &devs), ==, 1);
	libusb_free_device_list(devs, TRUE);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_ERROR, "\\[usbi_get_context\\].*implicit default");

	/* Only warns once */
	g_assert_cmpint(libusb_get_device_list(NULL, &devs), ==, 1);
	libusb_free_device_list(devs, TRUE);
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_INFO);

	libusb_init_context(/*ctx=*/NULL, /*options=*/NULL, /*num_options=*/0);
	g_assert_cmpint(libusb_get_device_list(NULL, &devs), ==, 1);
	libusb_exit(NULL);

	/* We free late, causing a warning from libusb_exit. However,
	 * we never see this warning (i.e. test success) because it is on a
	 * different context.
	 */
	libusb_free_device_list(devs, TRUE);
}

static void
test_close_flying(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	UsbChat chat[] = {
		{
		  .submit = TRUE,
		  .type = USBDEVFS_URB_TYPE_BULK,
		  .endpoint = LIBUSB_ENDPOINT_OUT,
		  .buffer = (unsigned char[]) { 0x01, 0x02, 0x03, 0x04 },
		  .buffer_length = 4,
		},
		{ .submit = FALSE }
	};
	libusb_device_handle *handle = NULL;
	struct libusb_transfer *transfer = NULL;

	test_fixture_set_chats(fixture->mocking, chat);

	/* Open */
	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	transfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(transfer,
				  handle,
				  LIBUSB_ENDPOINT_OUT,
				  (unsigned char*) chat[0].buffer,
				  chat[0].buffer_length,
				  NULL,
				  NULL,
				  1);

	/* Submit */
	libusb_submit_transfer(transfer);

	/* Closing logs fat error (two lines) */
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);
	libusb_close(handle);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_ERROR, "\\[do_close\\] .*connected as far as we know");
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_ERROR, "\\[do_close\\] .*cancellation hasn't even been scheduled");
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "\\[do_close\\] Removed transfer");

	/* Free'ing the transfer works, and logs to the right context */
	libusb_free_transfer(transfer);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "\\[libusb_free_transfer\\]");
}

static void
test_close_cancelled(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	UsbChat chat[] = {
		{
		  .submit = TRUE,
		  .type = USBDEVFS_URB_TYPE_BULK,
		  .endpoint = LIBUSB_ENDPOINT_OUT,
		  .buffer = (unsigned char[]) { 0x01, 0x02, 0x03, 0x04 },
		  .buffer_length = 4,
		},
		{ .submit = FALSE }
	};
	libusb_device_handle *handle = NULL;
	struct libusb_transfer *transfer = NULL;

	test_fixture_set_chats(fixture->mocking, chat);

	/* Open */
	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	transfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(transfer,
				  handle,
				  LIBUSB_ENDPOINT_OUT,
				  (unsigned char*) chat[0].buffer,
				  chat[0].buffer_length,
				  NULL,
				  NULL,
				  1);

	/* Submit */
	libusb_submit_transfer(transfer);
	libusb_cancel_transfer(transfer);

	/* Closing logs fat error (two lines) */
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);
	libusb_close(handle);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_ERROR, "\\[do_close\\] .*connected as far as we know");
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_WARNING, "\\[do_close\\] .*cancellation.*hasn't completed");
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_DEBUG, "\\[do_close\\] Removed transfer");

	libusb_free_transfer(transfer);
}

static void
test_ctx_destroy(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	UsbChat chat[] = {
		{
		  .submit = TRUE,
		  .type = USBDEVFS_URB_TYPE_BULK,
		  .endpoint = LIBUSB_ENDPOINT_OUT,
		  .buffer = (unsigned char[]) { 0x01, 0x02, 0x03, 0x04 },
		  .buffer_length = 4,
		},
		{ .submit = FALSE }
	};
	libusb_device_handle *handle = NULL;
	struct libusb_transfer *transfer = NULL;

	test_fixture_set_chats(fixture->mocking, chat);

	/* Open */
	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	transfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(transfer,
				  handle,
				  LIBUSB_ENDPOINT_OUT,
				  (unsigned char*) chat[0].buffer,
				  chat[0].buffer_length,
				  NULL,
				  NULL,
				  1);

	/* Submit */
	libusb_submit_transfer(transfer);

	/* Now we are evil and destroy the ctx! */
	libusb_exit(fixture->ctx);

	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_WARNING, "\\[libusb_exit\\] device.*still referenced");
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_WARNING, "\\[libusb_exit\\] application left some devices open");

	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);
	fixture->ctx = NULL;

	/* XXX: Closing crashes the application as it unref's the NULL pointer */
	/* libusb_close(handle); */

	libusb_free_transfer(transfer);
}

static void
test_get_string_descriptor(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	unsigned char data[255] = { 0, };
	libusb_device_handle *handle = NULL;
	UsbChat chat[] = {
		{
		  .submit = TRUE,
		  .reaps = &chat[1],
		  .type = USBDEVFS_URB_TYPE_CONTROL,
		  .buffer_length = 12, /* 8 byte out*/
		  .buffer = (const unsigned char*) "\x80\x06\x00\x03\x00\x00\x04\x00",
		}, {
		  /* String with content 0x0409 (en_US) */
		  .reap = TRUE,
		  .actual_length = 12,
		  .buffer = (const unsigned char*) "\x80\x06\x00\x03\x00\x00\x04\x00\x04\x03\x09\x04",
		}, {
		  .submit = TRUE,
		  .reaps = &chat[3],
		  .type = USBDEVFS_URB_TYPE_CONTROL,
		  .buffer_length = 263, /* 8 byte out*/
		  .buffer = (const unsigned char*) "\x80\x06\x01\x03\x09\x04\xff\x00",
		}, {
		  /* 4 byte string, "ab" */
		  .reap = TRUE,
		  .actual_length = 14,
		  .buffer = (const unsigned char*) "\x80\x06\x01\x03\x09\x04\xff\x00\x06\x03\x61\x00\x62\x00",
		}, {
		  .submit = TRUE,
		  .reaps = &chat[5],
		  .type = USBDEVFS_URB_TYPE_CONTROL,
		  .buffer_length = 12, /* 8 byte out*/
		  .buffer = (const unsigned char*) "\x80\x06\x00\x03\x00\x00\x04\x00",
		}, {
		  .reap = TRUE,
		  .status = -ENOENT,
		}, {
		  .submit = TRUE,
		  .status = -ENOENT,
		  .type = USBDEVFS_URB_TYPE_CONTROL,
		  .buffer_length = 12, /* 8 byte out*/
		  .buffer = (const unsigned char*) "\x80\x06\x00\x03\x00\x00\x04\x00",
		}, {
		  .submit = FALSE,
		}
	};

	test_fixture_set_chats(fixture->mocking, chat);

	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	/* The chat allows us to fetch the descriptor */
	g_assert_cmpint(libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)), ==, 2);
	g_assert_cmpint(memcmp(data, "ab", 2), ==, 0);
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);

	/* Again, but the URB fails with ENOENT when reaping */
	g_assert_cmpint(libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)), ==, -1);
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);

	/* Again, but the URB fails to submit with ENOENT */
	g_assert_cmpint(libusb_get_string_descriptor_ascii(handle, 1, data, sizeof(data)), ==, -1);
	assert_libusb_log_msg(fixture, LIBUSB_LOG_LEVEL_ERROR, "\\[submit_control_transfer\\] submiturb failed, errno=2");
	clear_libusb_log(fixture, LIBUSB_LOG_LEVEL_DEBUG);

	libusb_close(handle);
}

static void
transfer_cb_inc_user_data(struct libusb_transfer *transfer)
{
	*(int*)transfer->user_data += 1;
}

static void
test_timeout(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	UsbChat chat[] = {
		{
		  .submit = TRUE,
		  .type = USBDEVFS_URB_TYPE_BULK,
		  .endpoint = LIBUSB_ENDPOINT_OUT,
		  .buffer = (unsigned char[]) { 0x01, 0x02, 0x03, 0x04 },
		  .buffer_length = 4,
		},
		{
		  .submit = FALSE,
		}
	};
	int completed = 0;
	libusb_device_handle *handle = NULL;
	struct libusb_transfer *transfer = NULL;

	test_fixture_set_chats(fixture->mocking, chat);

	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	transfer = libusb_alloc_transfer(0);
	libusb_fill_bulk_transfer(transfer,
				  handle,
				  LIBUSB_ENDPOINT_OUT,
				  (unsigned char*) chat[0].buffer,
				  chat[0].buffer_length,
				  transfer_cb_inc_user_data,
				  &completed,
				  10);

	libusb_submit_transfer(transfer);
	while (!completed) {
		g_assert_cmpint(libusb_handle_events_completed(fixture->ctx, &completed), ==, 0);
		/* Silence after one iteration. */
		fixture->libusb_log_silence = TRUE;
	}
	fixture->libusb_log_silence = FALSE;

	g_assert_cmpint(transfer->status, ==, LIBUSB_TRANSFER_TIMED_OUT);
	libusb_free_transfer(transfer);

	libusb_close(handle);
}

#define THREADED_SUBMIT_URB_SETS 64
#define THREADED_SUBMIT_URB_IN_FLIGHT 64
typedef struct {
	struct libusb_transfer *transfers[THREADED_SUBMIT_URB_IN_FLIGHT * THREADED_SUBMIT_URB_SETS];
	int submitted;
	int completed;
	int done;
	UMockdevTestbedFixture *fixture;
} TestThreadedSubmit;

static gpointer
transfer_submit_all_retry(TestThreadedSubmit *data)
{
	for (guint i = 0; i < G_N_ELEMENTS(data->transfers); i++) {
		while (libusb_submit_transfer(data->transfers[i]) < 0) {
			assert_libusb_log_msg(data->fixture, LIBUSB_LOG_LEVEL_ERROR, "submit_bulk_transfer");
			continue;
		}

		data->submitted += 1;
	}

	return NULL;
}

static void
test_threaded_submit_transfer_cb(struct libusb_transfer *transfer)
{
	TestThreadedSubmit *data = transfer->user_data;

	/* We should only be receiving packets in the main thread */
	g_assert_cmpint (getpid(), ==, gettid());

	/* Check that the transfer buffer has the expected value */
	g_assert_cmpint (*(int*)transfer->buffer, ==, data->completed);
	data->completed += 1;

	if (data->completed == G_N_ELEMENTS(data->transfers))
		data->done = TRUE;
}

static void
test_threaded_submit(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	GThread *thread = NULL;
	TestThreadedSubmit data = { .fixture = fixture };
	UsbChat out_msg = {
		  .submit = TRUE,
		  .type = USBDEVFS_URB_TYPE_BULK,
		  .endpoint = LIBUSB_ENDPOINT_IN,
		  .buffer_length = sizeof(int),
	};
	UsbChat in_msg = {
		  .reap = TRUE,
		  .actual_length = 4,
	};
	UsbChat *c;
	libusb_device_handle *handle = NULL;
	int urb;

	handle = libusb_open_device_with_vid_pid(fixture->ctx, 0x04a9, 0x31c0);
	g_assert_nonnull(handle);

	fixture->libusb_log_silence = TRUE;

	c = g_new0(UsbChat, G_N_ELEMENTS(data.transfers) * 2 + 1);
	urb = 0;
	for (int i = 0; i < THREADED_SUBMIT_URB_SETS; i++) {
		for (int j = 0; j < THREADED_SUBMIT_URB_IN_FLIGHT; j++) {
			c[i*2*THREADED_SUBMIT_URB_IN_FLIGHT + j] = out_msg;
			c[i*2*THREADED_SUBMIT_URB_IN_FLIGHT + j].reaps = &c[(i*2+1)*THREADED_SUBMIT_URB_IN_FLIGHT + j];
			c[(i*2+1)*THREADED_SUBMIT_URB_IN_FLIGHT + j] = in_msg;
			c[(i*2+1)*THREADED_SUBMIT_URB_IN_FLIGHT + j].buffer = (unsigned char*) g_new0(int, 1);
			*(int*) c[(i*2+1)*THREADED_SUBMIT_URB_IN_FLIGHT + j].buffer = urb;

			data.transfers[urb] = libusb_alloc_transfer(0);
			libusb_fill_bulk_transfer(data.transfers[urb],
						  handle,
						  LIBUSB_ENDPOINT_IN,
						  g_malloc(out_msg.buffer_length),
						  out_msg.buffer_length,
						  test_threaded_submit_transfer_cb,
						  &data,
						  G_MAXUINT);
			data.transfers[urb]->flags = LIBUSB_TRANSFER_FREE_BUFFER | LIBUSB_TRANSFER_FREE_TRANSFER;
			urb++;
		}
	}

	test_fixture_set_chats(fixture->mocking, c);

	thread = g_thread_new("transfer all", (GThreadFunc) transfer_submit_all_retry, &data);

	while (!data.done)
		g_assert_cmpint(libusb_handle_events_completed(fixture->ctx, &data.done), ==, 0);

	g_thread_join(thread);

	fixture->libusb_log_silence = FALSE;
	libusb_close(handle);

	for (int i = 0; i < 2 * THREADED_SUBMIT_URB_SETS * THREADED_SUBMIT_URB_SETS; i++)
		g_clear_pointer ((void**) &c->buffer, g_free);
	g_free (c);
}

static int
hotplug_count_arrival_cb(libusb_context *ctx,
                         libusb_device  *device,
                         libusb_hotplug_event event,
                         void *user_data)
{
	g_assert_cmpint(event, ==, LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED);

	(void) ctx;
	(void) device;

	*(int*) user_data += 1;

	return 0;
}

#ifdef UMOCKDEV_HOTPLUG
static int
hotplug_count_removal_cb(libusb_context *ctx,
                         libusb_device  *device,
                         libusb_hotplug_event event,
                         void *user_data)
{
	g_assert_cmpint(event, ==, LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT);

	(void) ctx;
	(void) device;

	*(int*) user_data += 1;

	return 0;
}
#endif

static void
test_hotplug_enumerate(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
	libusb_hotplug_callback_handle handle_enumerate;
	libusb_hotplug_callback_handle handle_no_enumerate;
	int event_count_enumerate = 0;
	int event_count_no_enumerate = 0;
	struct timeval zero_tv = { 0 };
	int r;

	r = libusb_hotplug_register_callback(fixture->ctx,
	                                     LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
	                                     LIBUSB_HOTPLUG_ENUMERATE,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     hotplug_count_arrival_cb,
	                                     &event_count_enumerate,
	                                     &handle_enumerate);
	g_assert_cmpint(r, ==, 0);

	r = libusb_hotplug_register_callback(fixture->ctx,
	                                     LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
	                                     0,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     hotplug_count_arrival_cb,
	                                     &event_count_no_enumerate,
	                                     &handle_no_enumerate);
	g_assert_cmpint(r, ==, 0);

	g_assert_cmpint(event_count_enumerate, ==, 1);
	g_assert_cmpint(event_count_no_enumerate, ==, 0);

	libusb_handle_events_timeout(fixture->ctx, &zero_tv);

	g_assert_cmpint(event_count_enumerate, ==, 1);
	g_assert_cmpint(event_count_no_enumerate, ==, 0);

	libusb_hotplug_deregister_callback(fixture->ctx, handle_enumerate);
	libusb_hotplug_deregister_callback(fixture->ctx, handle_no_enumerate);

	libusb_handle_events_timeout(fixture->ctx, &zero_tv);

	g_assert_cmpint(event_count_enumerate, ==, 1);
	g_assert_cmpint(event_count_no_enumerate, ==, 0);
}

static void
test_hotplug_add_remove(UMockdevTestbedFixture * fixture, UNUSED_DATA)
{
#ifdef UMOCKDEV_HOTPLUG
	libusb_device **devs = NULL;
	libusb_hotplug_callback_handle handle_add;
	libusb_hotplug_callback_handle handle_remove;
	int event_count_add = 0;
	int event_count_remove = 0;
	struct timeval zero_tv = { 0 };
	int r;

	r = libusb_hotplug_register_callback(fixture->ctx,
	                                     LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED,
	                                     LIBUSB_HOTPLUG_ENUMERATE,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     hotplug_count_arrival_cb,
	                                     &event_count_add,
	                                     &handle_add);
	g_assert_cmpint(r, ==, 0);

	r = libusb_hotplug_register_callback(fixture->ctx,
	                                     LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
	                                     LIBUSB_HOTPLUG_ENUMERATE,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     LIBUSB_HOTPLUG_MATCH_ANY,
	                                     hotplug_count_removal_cb,
	                                     &event_count_remove,
	                                     &handle_remove);
	g_assert_cmpint(r, ==, 0);

	/* No device, even going into the mainloop will not call cb. */
	libusb_handle_events_timeout(fixture->ctx, &zero_tv);
	g_assert_cmpint(event_count_add, ==, 0);
	g_assert_cmpint(event_count_remove, ==, 0);

	/* Add a device */
	test_fixture_add_canon(fixture->mocking);

	/* Either the thread has picked it up already, or we do so now. */
	g_assert_cmpint(libusb_get_device_list(fixture->ctx, &devs), ==, 1);
	libusb_free_device_list(devs, TRUE);

	/* The hotplug event is pending now, but has not yet fired. */
	g_assert_cmpint(event_count_add, ==, 0);
	g_assert_cmpint(event_count_remove, ==, 0);

	/* Fire hotplug event. */
	libusb_handle_events_timeout(fixture->ctx, &zero_tv);
	g_assert_cmpint(event_count_add, ==, 1);
	g_assert_cmpint(event_count_remove, ==, 0);

	// TODO: uncomment this: umockdev_testbed_uevent(fixture->testbed, "/sys/devices/usb1", "remove");
	// umockdev_testbed_remove_device(fixture->testbed, "/devices/usb1");

	/* Either the thread has picked it up already, or we do so now. */
	g_assert_cmpint(libusb_get_device_list(fixture->ctx, &devs), ==, 0);
	libusb_free_device_list(devs, TRUE);

	/* The hotplug event is pending now, but has not yet fired. */
	g_assert_cmpint(event_count_add, ==, 1);
	g_assert_cmpint(event_count_remove, ==, 0);

	/* Fire hotplug event. */
	libusb_handle_events_timeout(fixture->ctx, &zero_tv);
	g_assert_cmpint(event_count_add, ==, 1);
	g_assert_cmpint(event_count_remove, ==, 1);

	libusb_hotplug_deregister_callback(fixture->ctx, handle_add);
	libusb_hotplug_deregister_callback(fixture->ctx, handle_remove);
#else
	(void) fixture;
	g_test_skip("UMockdev is too old to test hotplug");
#endif
}

int
main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add("/libusb/open-close", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_open_close,
	           test_fixture_teardown);

	g_test_add("/libusb/implicit-default", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_implicit_default,
	           test_fixture_teardown);

	g_test_add("/libusb/close-flying", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_close_flying,
	           test_fixture_teardown);
	g_test_add("/libusb/close-cancelled", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_close_cancelled,
	           test_fixture_teardown);

	g_test_add("/libusb/ctx-destroy", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_ctx_destroy,
	           test_fixture_teardown);

	g_test_add("/libusb/string-descriptor", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_get_string_descriptor,
	           test_fixture_teardown);

	g_test_add("/libusb/timeout", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_timeout,
	           test_fixture_teardown);

	g_test_add("/libusb/threaded-submit", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_threaded_submit,
	           test_fixture_teardown);

	g_test_add("/libusb/hotplug/enumerate", UMockdevTestbedFixture, NULL,
	           test_fixture_setup_with_canon,
	           test_hotplug_enumerate,
	           test_fixture_teardown);

	// g_test_add("/libusb/hotplug/add-remove", UMockdevTestbedFixture, NULL,
	//            test_fixture_setup_empty,
	//            test_hotplug_add_remove,
	//            test_fixture_teardown);

	return g_test_run();
}

#include <linux/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <umockdev.h>

#include "libusb.h"

#include "umockdev-server.h"

typedef struct _UsbChat UsbChat;

struct _UsbChat {
	gboolean submit;
	gboolean reap;
	UsbChat *reaps;
	UsbChat *next;

	/* struct usbdevfs_urb */
	unsigned char type;
	unsigned char endpoint;
	int status;
	unsigned int flags;
	const unsigned char *buffer;
	int buffer_length;
	int actual_length;

	/* <submit urb> */
	UMockdevIoctlData *submit_urb;
};

struct _MockingFixture {
	UMockdevTestbed *testbed;
	UMockdevIoctlBase *handler;

	gchar *root_dir;
	gchar *sys_dir;

	UsbChat *chat;
	GList *flying_urbs;
	GList *discarded_urbs;

	/* GMutex confuses tsan unecessarily */
	pthread_mutex_t mutex;
};

static gint
cmp_ioctl_data_addr(const void *data, const void *addr)
{
	return ((const UMockdevIoctlData*) data)->client_addr != (gulong) addr;
}

static void
dump_buffer(const unsigned char *buffer, int len)
{
	g_autoptr(GString) line = NULL;

	line = g_string_new ("");
	for (gint i = 0; i < len; i++) {
		g_string_append_printf(line, "%02x ", buffer[i]);
		if ((i + 1) % 16 == 0) {
			g_printerr("    %s\n", line->str);
			g_string_set_size(line, 0);
		}
	}

	if (line->len)
		g_printerr("    %s\n", line->str);
}

static gboolean
handle_ioctl_cb (UMockdevIoctlBase *handler, UMockdevIoctlClient *client, MockingFixture *fixture)
{
	UMockdevIoctlData *ioctl_arg;
	long int request;
	struct usbdevfs_urb *urb;

	(void) handler;

	request = umockdev_ioctl_client_get_request (client);
	ioctl_arg = umockdev_ioctl_client_get_arg (client);

	/* NOTE: We share the address space, dereferencing pointers *will* work.
	 * However, to make tsan work, we still stick to the API that resolves
	 * the data into a local copy! */

	switch (request) {
	case USBDEVFS_GET_CAPABILITIES: {
		g_autoptr(UMockdevIoctlData) d = NULL;
		d = umockdev_ioctl_data_resolve(ioctl_arg, 0, sizeof(guint32), NULL);

		*(guint32*) d->data = USBDEVFS_CAP_BULK_SCATTER_GATHER |
				      USBDEVFS_CAP_BULK_CONTINUATION |
				      USBDEVFS_CAP_NO_PACKET_SIZE_LIM |
				      USBDEVFS_CAP_REAP_AFTER_DISCONNECT |
				      USBDEVFS_CAP_ZERO_PACKET;

		umockdev_ioctl_client_complete(client, 0, 0);
		return TRUE;
	}

	case USBDEVFS_CLAIMINTERFACE:
	case USBDEVFS_RELEASEINTERFACE:
	case USBDEVFS_CLEAR_HALT:
	case USBDEVFS_RESET:
	case USBDEVFS_RESETEP:
		umockdev_ioctl_client_complete(client, 0, 0);
		return TRUE;

	case USBDEVFS_SUBMITURB: {
		g_autoptr(UMockdevIoctlData) urb_buffer = NULL;
		g_autoptr(UMockdevIoctlData) urb_data = NULL;
		gsize buflen;

		if (!fixture->chat || !fixture->chat->submit)
			return FALSE;

		buflen = fixture->chat->buffer_length;
		if (fixture->chat->type == USBDEVFS_URB_TYPE_CONTROL)
			buflen = 8;

		urb_data = umockdev_ioctl_data_resolve(ioctl_arg, 0, sizeof(struct usbdevfs_urb), NULL);
		urb = (struct usbdevfs_urb*) urb_data->data;
		urb_buffer = umockdev_ioctl_data_resolve(urb_data, G_STRUCT_OFFSET(struct usbdevfs_urb, buffer), urb->buffer_length, NULL);

		if (fixture->chat->type == urb->type &&
		    fixture->chat->endpoint == urb->endpoint &&
		    fixture->chat->buffer_length == urb->buffer_length &&
		    (fixture->chat->buffer == NULL || memcmp (fixture->chat->buffer, urb_buffer->data, buflen) == 0)) {
			fixture->flying_urbs = g_list_append (fixture->flying_urbs, umockdev_ioctl_data_ref(urb_data));

			if (fixture->chat->reaps)
				fixture->chat->reaps->submit_urb = urb_data;

			if (fixture->chat->status)
				umockdev_ioctl_client_complete(client, -1, -fixture->chat->status);
			else
				umockdev_ioctl_client_complete(client, 0, 0);

			if (fixture->chat->next)
				fixture->chat = fixture->chat->next;
			else
				fixture->chat += 1;
			return TRUE;
		}

		/* chat message didn't match, don't accept it */
		g_printerr("Could not process submit urb:\n");
		g_printerr(" t: %d, ep: %d, actual_length: %d, buffer_length: %d\n",
			   urb->type, urb->endpoint, urb->actual_length, urb->buffer_length);
		if (urb->type == USBDEVFS_URB_TYPE_CONTROL || urb->endpoint & LIBUSB_ENDPOINT_IN)
			dump_buffer(urb->buffer, urb->buffer_length);
		g_printerr("Looking for:\n");
		g_printerr(" t: %d, ep: %d, actual_length: %d, buffer_length: %d\n",
			   fixture->chat->type, fixture->chat->endpoint,
			   fixture->chat->actual_length, fixture->chat->buffer_length);
		if (fixture->chat->buffer)
			dump_buffer(fixture->chat->buffer, buflen);

		return FALSE;
	}

	case USBDEVFS_REAPURB:
	case USBDEVFS_REAPURBNDELAY: {
		g_autoptr(UMockdevIoctlData) urb_ptr = NULL;
		g_autoptr(UMockdevIoctlData) urb_data = NULL;

		if (fixture->discarded_urbs) {
			urb_data = fixture->discarded_urbs->data;
			urb = (struct usbdevfs_urb*) urb_data->data;
			fixture->discarded_urbs = g_list_delete_link(fixture->discarded_urbs, fixture->discarded_urbs);
			urb->status = -ENOENT;

			urb_ptr = umockdev_ioctl_data_resolve(ioctl_arg, 0, sizeof(gpointer), NULL);
			umockdev_ioctl_data_set_ptr(urb_ptr, 0, urb_data);

			umockdev_ioctl_client_complete(client, 0, 0);
			return TRUE;
		}

		if (fixture->chat && fixture->chat->reap) {
			GList *l = g_list_find(fixture->flying_urbs, fixture->chat->submit_urb);

			if (l) {
				fixture->flying_urbs = g_list_remove_link(fixture->flying_urbs, fixture->flying_urbs);

				urb_data = fixture->chat->submit_urb;
				urb = (struct usbdevfs_urb*) urb_data->data;
				urb->actual_length = fixture->chat->actual_length;
				if (urb->type == USBDEVFS_URB_TYPE_CONTROL && urb->actual_length)
					urb->actual_length -= 8;
				if (fixture->chat->buffer)
					memcpy(urb->buffer, fixture->chat->buffer, fixture->chat->actual_length);
				urb->status = fixture->chat->status;

				urb_ptr = umockdev_ioctl_data_resolve(ioctl_arg, 0, sizeof(gpointer), NULL);
				umockdev_ioctl_data_set_ptr(urb_ptr, 0, urb_data);
				if (fixture->chat->next)
					fixture->chat = fixture->chat->next;
				else
					fixture->chat += 1;
				umockdev_ioctl_client_complete(client, 0, 0);
				return TRUE;
			}
		}

		/* Nothing to reap */
		umockdev_ioctl_client_complete(client, -1, EAGAIN);
		return TRUE;
	}

	case USBDEVFS_DISCARDURB: {
		GList *l = g_list_find_custom(fixture->flying_urbs, *(void**) ioctl_arg->data, cmp_ioctl_data_addr);

		if (l) {
			fixture->discarded_urbs = g_list_append(fixture->discarded_urbs, l->data);
			fixture->flying_urbs = g_list_delete_link(fixture->flying_urbs, l);
			umockdev_ioctl_client_complete(client, 0, 0);
		} else {
			umockdev_ioctl_client_complete(client, -1, EINVAL);
		}

		return TRUE;
	}

	default:
		return FALSE;
	}
}

MockingFixture*
test_fixture_setup_mocking()
{
	MockingFixture *fixture = g_new0(MockingFixture, 1);

	fixture->testbed = umockdev_testbed_new();
	g_assert(fixture->testbed != NULL);
	fixture->root_dir = umockdev_testbed_get_root_dir(fixture->testbed);
	fixture->sys_dir = umockdev_testbed_get_sys_dir(fixture->testbed);

	fixture->handler = umockdev_ioctl_base_new();
	g_object_connect(fixture->handler, "signal-after::handle-ioctl", handle_ioctl_cb, fixture, NULL);

	return fixture;
}

void
test_fixture_teardown_mocking(MockingFixture * fixture)
{
	g_clear_object(&fixture->handler);
	g_clear_object(&fixture->testbed);

	/* verify that temp dir gets cleaned up properly */
	g_assert(!g_file_test(fixture->root_dir, G_FILE_TEST_EXISTS));
	g_free(fixture->root_dir);
	g_free(fixture->sys_dir);

	while (fixture->flying_urbs) {
		umockdev_ioctl_data_unref (fixture->flying_urbs->data);
		fixture->flying_urbs = g_list_delete_link (fixture->flying_urbs, fixture->flying_urbs);
	}
}

void
test_fixture_add_canon(MockingFixture * fixture)
{
	/* Setup first, so we can be sure libusb_open works when the add uevent
	 * happens.
	 */
	g_assert_cmpint(umockdev_testbed_attach_ioctl(fixture->testbed, "/dev/bus/usb/001/001", fixture->handler, NULL), ==, 1);

	/* NOTE: add_device would not create a file, needed for device emulation */
	/* XXX: Racy, see https://github.com/martinpitt/umockdev/issues/173 */
	umockdev_testbed_add_from_string(fixture->testbed,
		"P: /devices/usb1\n"
		"N: bus/usb/001/001\n"
		"E: SUBSYSTEM=usb\n"
		"E: DRIVER=usb\n"
		"E: BUSNUM=001\n"
		"E: DEVNUM=001\n"
		"E: DEVNAME=/dev/bus/usb/001/001\n"
		"E: DEVTYPE=usb_device\n"
		"A: bConfigurationValue=1\\n\n"
		"A: busnum=1\\n\n"
		"A: devnum=1\\n\n"
		"A: bConfigurationValue=1\\n\n"
		"A: speed=480\\n\n"
		/* descriptor from a Canon PowerShot SX200; VID 04a9 PID 31c0 */
		"H: descriptors="
		  "1201000200000040a904c03102000102"
		  "030109022700010100c0010904000003"
		  "06010100070581020002000705020200"
		  "020007058303080009\n",
		NULL);
}

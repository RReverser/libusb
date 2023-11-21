typedef struct _MockingFixture MockingFixture;

MockingFixture* test_fixture_setup_mocking(void);
void test_fixture_add_canon(MockingFixture * fixture);
void test_fixture_teardown_mocking(MockingFixture * fixture);

typedef struct _UsbChat UsbChat;

struct _UsbChat {
	gboolean submit;
	gboolean reap;
	int reaps_offset;
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
	struct _UMockdevIoctlData *submit_urb;
};

void test_fixture_set_chats(MockingFixture * fixture, UsbChat * chat);

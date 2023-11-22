#include <stdbool.h>

typedef struct _MockingFixture MockingFixture;

typedef struct _UsbChat UsbChat;

struct _UsbChat {
	bool submit;
	bool reap;
	int reaps_offset;

	/* struct usbdevfs_urb */
	unsigned char type;
	unsigned char endpoint;
	int status;
	unsigned int flags;
	int actual_length;
	const unsigned char *buffer;
	int buffer_length;

	/* <submit urb> */
	struct _UMockdevIoctlData *submit_urb;
};

#ifdef __cplusplus
extern "C" {
#endif

MockingFixture* test_fixture_setup_mocking(void);
void test_fixture_add_canon(MockingFixture * fixture);
void test_fixture_remove_canon(MockingFixture * fixture);
void test_fixture_teardown_mocking(MockingFixture * fixture);
void test_fixture_set_chats(MockingFixture * fixture, UsbChat * chat);

#ifdef __cplusplus
}
#endif

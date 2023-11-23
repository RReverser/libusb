#include <stdbool.h>
#include <stddef.h>

typedef struct MockingFixture MockingFixture;

typedef struct UsbChat {
	bool submit;
	int reaps_offset;

	/* struct usbdevfs_urb */
	unsigned char type;
	unsigned char endpoint;
	int status;
	unsigned int flags;
	const unsigned char *buffer;
	int buffer_length;
	int actual_length;

	/* <submit urb> */
	struct _UMockdevIoctlData *reap_submit_urb;
} UsbChat;

#ifdef __cplusplus
extern "C" {
#endif

MockingFixture* test_fixture_setup_mocking(void);
void test_fixture_add_canon(MockingFixture * fixture);
void test_fixture_remove_canon(MockingFixture * fixture);
void test_fixture_teardown_mocking(MockingFixture * fixture);
void test_fixture_set_chats(MockingFixture * fixture, UsbChat * chat, size_t nchats);

#ifdef __cplusplus
}
#endif

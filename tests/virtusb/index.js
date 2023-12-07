const { SimulatedUsbDevice, UsbIpServerSim } = require('node_usbip_server');

/**
 * @typedef {import('node_usbip_server').SimulatedUsbDeviceEndpoint} SimulatedUsbDeviceEndpoint
 */

/** @type {string[]} */
let stringDescriptors = [];

const DIRECTION = /** @type {const} */ ({
  OUT: 0,
  IN: 1
});

/**
 * @param {number} wMaxPacketSize
 * @returns {SimulatedUsbDeviceEndpoint}
 */
function makeControlEndpoint(wMaxPacketSize) {
  return {
    bEndpointAddress: {
      // (ignored for control endpoints)
      direction: DIRECTION.OUT
    },
    bmAttributes: {
      // Control endpoint.
      transferType: 0b00
    },
    wMaxPacketSize: 64,
    // (ignored for control endpoints)
    bInterval: 0
  };
}

/**
 * @param {keyof DIRECTION} direction
 * @param {number} wMaxPacketSize
 * @returns {SimulatedUsbDeviceEndpoint}
 */
function makeBulkEndpoint(direction, wMaxPacketSize) {
  return {
    bEndpointAddress: {
      direction: DIRECTION[direction]
    },
    bmAttributes: {
      // Bulk endpoint.
      transferType: 0b10
    },
    wMaxPacketSize,
    // (ignored for bulk endpoints)
    bInterval: 0
  };
}

let testDevice = new SimulatedUsbDevice({
  // pid.codes VID used for OSS projects.
  idVendor: 0x1209,
  // PID reserved for testing.
  idProduct: 0x0001,

  // Encoded device version 1.2.3 for easy comparison.
  bcdDevice: (1 << 8) | (2 << 4) | 3,

  bcdUSB: '2.1.0',

  // Vendor-specific device class.
  bDeviceClass: 0xff,
  // Just some recognisable subclass & protocol.
  bDeviceSubClass: 0x12,
  bDeviceProtocol: 0x13,

  // High speed device.
  speed: 3,
  bMaxPacketSize0: 64,

  iManufacturer: stringDescriptors.push('libusb'),
  iProduct: stringDescriptors.push('libusb emulated device'),
  iSerialNumber: stringDescriptors.push('1234567890'),

  configurations: [
    // TODO: test multiple configurations.
    {
      // Arbitrary configuration value order to verify that the backend finds config by value correctly.
      bConfigurationValue: 10,
      bmAttributes: {
        selfPowered: true,
        remoteWakeup: false
      },
      bMaxPower: 50,
      iConfiguration: stringDescriptors.push('Config #0'),
      // TODO: test multiple alternates.
      interfaces: [
        {
          iInterface: stringDescriptors.push('Config #0 -> Interface #0'),

          bInterfaceClass: 0xff,
          bInterfaceSubClass: 0x14,
          bInterfaceProtocol: 0x15,

          endpoints: [
            makeControlEndpoint(64),
            makeBulkEndpoint(
              'OUT',
              // different value just to verify backend can handle it correctly
              128
            ),
            makeBulkEndpoint(
              'IN',
              // different value just to verify backend can handle it correctly
              256
            )
            // TODO: add isochronous and interrupt endpoints.
          ]
        }
      ]
    }
  ],

  // TODO: test support for multiple languages.
  supportedLangs: [0x0409],
  // Important: this must be somewhere at the end, after all the `stringDescriptors.push` calls.
  stringDescriptors
});

let server = new UsbIpServerSim({
  // The only official USB/IP version.
  version: '1.1.1',
});

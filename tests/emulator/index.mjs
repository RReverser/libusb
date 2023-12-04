import jBinary from 'jbinary';
import { createServer } from 'node:net';
import assert from 'node:assert';

let uniquePaddingNameCounter = 0;

function padding(size) {
  return {
    [`_padding${uniquePaddingNameCounter++}`]: ['skip', size]
  };
}

const typeSet = {
  switch: jBinary.Template({
    params: ['discriminant', 'variants'],

    resolve(getType) {
      for (let [key, type] of Object.entries(this.variants)) {
        this.variants[key] = getType(type);
      }
    },

    getBaseType() {
      return this.variants[this.toValue(this.discriminant)];
    }
  }),

  Version: ['const', 'uint16', 0x0111, true],

  PrefixedArray: jBinary.Template({
    setParams(lenType, itemType) {
      this.baseType = {
        len: lenType,
        items: ['array', itemType, 'len']
      };
    },
    read() {
      return this.baseRead().items;
    },
    write(arr) {
      this.baseWrite({ len: arr.length, items: arr });
    }
  }),

  OpReq: [
    'extend',
    {
      version: 'Version',
      command: ['enum', 'uint16', { devList: 0x8005, import: 0x8003 }],
      status: ['const', 'int32', 0]
    },
    [
      'switch',
      'command',
      {
        devList: {},
        import: {
          busId: ['string0', 32]
        }
      }
    ]
  ],

  DeviceHeader: {
    path: ['string0', 256],
    busId: ['string0', 32],
    busNum: 'uint32',
    devNum: 'uint32',
    speed: 'uint32',
    idVendor: 'uint16',
    idProduct: 'uint16',
    bcdDevice: 'uint16',
    bDeviceClass: 'uint8',
    bDeviceSubClass: 'uint8',
    bDeviceProtocol: 'uint8',
    bConfigurationValue: 'uint8',
    bNumConfigurations: 'uint8'
  },

  DevlistDevice: [
    'extend',
    'DeviceHeader',
    {
      interfaces: [
        'PrefixedArray',
        'uint8',
        {
          bInterfaceClass: 'uint8',
          bInterfaceSubClass: 'uint8',
          bInterfaceProtocol: 'uint8',
          ...padding(1)
        }
      ]
    }
  ],

  ImportDevice: [
    'extend',
    'DeviceHeader',
    {
      bNumInterfaces: 'uint8'
    }
  ],

  OpRepDevlist: {
    version: 'Version',
    replyCode: ['const', 'uint16', 0x0005, true],
    status: 'int32',
    devices: ['PrefixedArray', 'uint32', 'DevlistDevice']
  },

  OpRepImport: {
    version: 'Version',
    replyCode: ['const', 'uint16', 0x0003, true],
    device: jBinary.Template({
      baseType: {
        status: ['enum', 'int32', { ok: 0, error: 1 }],
        maybeDevice: ['if', ctx => ctx.status === 'ok', 'ImportDevice']
      },
      read() {
        return this.baseRead().maybeDevice;
      },
      write(value) {
        this.baseWrite({ status: value ? 'ok' : 'error', maybeDevice: value });
      }
    })
  },

  UsbipCmdSubmitSufix: {
    transferFlags: 'uint32',
    transferBufferLength: 'uint32',
    startFrame: 'uint32',
    numberOfPackets: ['const', 'int32', -1, true], // TODO: ISO packets
    interval: 'uint32',
    setup: ['array', 'uint8', 8],
    transferBuffer: [
      'if',
      ctx => ctx.direction === 'out',
      ['array', 'uint8', 'transferBufferLength']
    ]
    // TODO: ISO packets
  },

  UsbipCmdUnlinkSuffix: {
    unlinkSeqNum: 'uint32',
    ...padding(24)
  },

  UsbIpCmd: [
    'extend',
    {
      command: [
        'enum',
        'uint32',
        {
          submit: 0x0001,
          unlink: 0x0002
        }
      ],
      seqNum: 'uint32',
      devId: 'uint32',
      direction: ['enum', 'uint32', { out: 0, in: 1 }],
      endpoint: 'uint32'
    },
    [
      'switch',
      'command',
      {
        submit: 'UsbipCmdSubmitSufix',
        unlink: 'UsbipCmdUnlinkSuffix'
      }
    ]
  ],

  UsbipHeaderRet: {
    command: 'uint32',
    seqNum: 'uint32',
    ...padding(12)
  },

  UsbipRetSubmit: [
    'extend',
    'UsbipHeaderRet',
    {
      command: ['const', 'uint32', 0x0003, true],
      status: 'int32',
      actualLength: 'uint32',
      startFrame: 'uint32',
      numberOfPackets: ['const', 'int32', -1, true], // TODO: ISO packets
      errorCount: 'uint32',
      ...padding(8),
      transferBuffer: [
        'if',
        ctx => ctx.direction === 'in',
        ['array', 'uint8', 'actualLength']
      ]
      // TODO: ISO packets
    }
  ],

  UsbipRetUnlink: [
    'extend',
    'UsbipHeaderRet',
    {
      command: ['const', 'uint32', 0x0004, true],
      status: 'int32',
      ...padding(24)
    }
  ]
};

createServer(socket => {
  let attached = false;

  for await (let inputMsg of socket) {
    console.log('Received message', inputMsg);
    let jb = new jBinary(inputMsg, typeSet);
    if (!attached) {
      let cmd = jb.read('OpReq');
    } else {
      console.log(jb.read('UsbIpCmd'));
    }
    assert.equal(jb.tell(), jb.view.byteLength);
  }
}).listen(3240);

console.log('Listening...');

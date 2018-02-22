const crypto = require('crypto')
const net = require('net')
const int24 = require('int24')
const x509 = require('x509')

const PROTO_MAJOR_VERSION = 3
const PROTO_MINOR_VERSION = 3

const CONTENT_TYPE = Object.freeze({
  HANDSHAKE: 22
})

const HANDSHAKE_TYPE = Object.freeze({
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  CERTIFICATE: 11
})

const COMPRESSION_METHODS = Object.freeze({
  NONE: Uint8Array.from([0x00])
})
const SUPPORTED_CIPHERS = Object.freeze({
  'TLS_RSA_WITH_AES_128_GCM_SHA256': Uint8Array.from([0x00, 0x9c])
})

const createProtocolVersionBuffer = () => {
  return Buffer.from(Uint8Array.from([PROTO_MAJOR_VERSION, PROTO_MINOR_VERSION]).buffer)
}

const createRecordLayerBuffer = (contentType, fragment) => {
  const protocolVersionBuffer = createProtocolVersionBuffer()

  const header = Buffer.alloc(5)
  header.writeUInt8(contentType, 0) // First byte is contentType
  protocolVersionBuffer.copy(header, 1) // Byte 2-3 - Protocol Version
  header.writeUInt16BE(fragment.length, 3) // Byte 4-5 - Length of fragment

  return Buffer.concat([header, fragment]) // Append fragement
}

const createHandshake = (handshakeType, body) => {
  const header = Buffer.alloc(4)
  header.writeUInt8(handshakeType, 0) // First byte is handshakeType
  int24.writeUInt24BE(header, 1, body.length)
  return Buffer.concat([header, body]) // Remaining bytes is the body
}

const getRandom = () => {
  const randomBuffer = Buffer.allocUnsafe(32)
  const randomBytes = crypto.randomBytes(28)

  const unixTimestampSeconds = Math.floor(new Date() / 1000)
  randomBuffer.writeUInt32BE(unixTimestampSeconds, 0) // Bytes 1-4 - Unix timestamp
  randomBytes.copy(randomBuffer, 4) // Bytes 5 - 32 - Random bytes
  return randomBuffer
}


const getCipherSuites = () => {
  const ciphers = Object.values(SUPPORTED_CIPHERS)
  const lengthBuffer = Buffer.alloc(2)
  lengthBuffer.writeUInt16BE(ciphers.length * 2) // Each cipher take up two bytes

  return Buffer.concat([lengthBuffer, ...ciphers])
}

const getCompressionMethods = () => {
  const compressionMethods = Object.values(COMPRESSION_METHODS)
  const length = compressionMethods.length
  return Buffer.from(Uint8Array.from([length, ...compressionMethods]).buffer)
}


const createClientHello = () => {
  const protocolVersionBuffer = createProtocolVersionBuffer()
  const randomBuffer = getRandom()
  const sessionIdLength = Uint8Array.from([0x00])
  const cipherSuites = getCipherSuites()
  const compressionMethods = getCompressionMethods()


  return Buffer.concat([
    protocolVersionBuffer,
    randomBuffer,
    sessionIdLength,
    cipherSuites,
    compressionMethods
  ])
}

const clientHello = createClientHello()
const clientHelloHandshake = createHandshake(HANDSHAKE_TYPE.CLIENT_HELLO, clientHello)
const clientHelloRecordLayer = createRecordLayerBuffer(CONTENT_TYPE.HANDSHAKE, clientHelloHandshake)

var client = new net.Socket();
client.connect(443, 'www.google.com', function() {
  console.log('Connected');
  client.write(clientHelloRecordLayer)
});

let data = Buffer.alloc(0)

client.on('data', function(newData) {
  console.log('NEW DATA')
  data = Buffer.concat([data, newData])

  handleRecordLayerStream(data)
});

client.on('end', function(data) {
  console.log('END FIRED')
});

client.on('close', function() {
  console.log('Connection closed');
});

const handleRecordLayerStream = (stream) => {
  const contentType = stream.readUInt8(0)
  const majorVersion = stream.readUInt8(1)
  const minorVersion = stream.readUInt8(2)

  if (majorVersion === PROTO_MAJOR_VERSION && minorVersion === PROTO_MINOR_VERSION) {
    const fragmentLength = stream.readUInt16BE(3)
    const fragmentStartByte = 5
    const fragmentEndByte = fragmentStartByte + fragmentLength

    if (fragmentEndByte > stream.length) {
      console.log('WE DONT HAVE THE FULL FRAGMENT IN THE BUFFER YET, HOLDING FOR MORE DATA')
      data = stream
    } else {
      const fragment = stream.slice(fragmentStartByte, fragmentEndByte)

      if (contentType === CONTENT_TYPE.HANDSHAKE) {
        handleHandshake(fragment)
      }
      else {
        console.log('UNSUPPORT CONTENT TYPE')
      }

      if (fragmentEndByte < stream.length) {
        const remainingStreamStart = fragmentEndByte
        const remainingStream = stream.slice(remainingStreamStart)
        handleRecordLayerStream(remainingStream)
      }
    }
  } else {
    console.log('Invalid data on on buffer')
  }
}

const handleHandshake = (fragment) => {
  const handshakeType = fragment.readUInt8(0)
  const bodyLength = int24.readUInt24BE(fragment, 1)
  const bodyStartByte = 4
  const bodyEndByte = bodyStartByte + bodyLength
  const body = fragment.slice(bodyStartByte)

  if (handshakeType === HANDSHAKE_TYPE.SERVER_HELLO) {
    handleServerHello(body)
  }
  else if (handshakeType === HANDSHAKE_TYPE.CERTIFICATE) {
    handleCertificate(body)
  } else {
    console.log('UNSUPPORTED HANDSHAKE_TYPE ' + handshakeType)
  }

}

const handleServerHello = (body) => {
  const majorVersion = body.readUInt8(0)
  const minorVersion = body.readUInt8(1)
  if (majorVersion === PROTO_MAJOR_VERSION && minorVersion === PROTO_MINOR_VERSION) {
    const serverRandom = body.slice(2, 34)
    const sessionIdLength = body.readUInt8(34)

    const sessionIdStart = 35
    const sessionIdEnd = sessionIdStart + sessionIdLength
    const sessionId = body.slice(sessionIdStart, sessionIdEnd)

    const cipherSuiteStart = sessionIdEnd
    const cipherSuiteEnd = sessionIdEnd + 2
    const cipherSuite = body.slice(cipherSuiteStart, cipherSuiteEnd)

    const compressionMethodStart = cipherSuiteEnd
    const compressionMethod = body.slice(compressionMethodStart, compressionMethodStart + 1)


    if (compressionMethod.equals(COMPRESSION_METHODS.NONE)) {
      if (cipherSuite.equals(SUPPORTED_CIPHERS.TLS_RSA_WITH_AES_128_GCM_SHA256)) {
        console.log('No compression')
        console.log('TLS_RSA_WITH_AES_128_GCM_SHA256')
      }
    }
  }
}

const handleCertificate = (body) => {
  const certificatesListLength = int24.readUInt24BE(body, 0)
  const certificatesList = body.slice(3)
  const certificates = getCertificatesFromList(certificatesList)
  console.log(`SERVER SENT ${certificates.length} CERTIFICATES`)
  certificates.forEach((cert, index) => {
    const certSubject = x509.getSubject(cert)
    console.log(`CERT ${index + 1} - Org: ${certSubject.organizationName}, CN: ${certSubject.commonName} `)
  })
}

const getCertificatesFromList = (certificatesList) => {
  const certLength = int24.readUInt24BE(certificatesList, 0)
  const certStart = 3
  const certEnd = 3 + certLength
  const certDER = certificatesList.slice(certStart, certEnd)
  const certPEM = getPEMCert(certDER)
  if (certEnd < certificatesList.length) {
    const remainingCerts = certificatesList.slice(certEnd)
    return [certPEM, ...getCertificatesFromList(remainingCerts)]
  }

  return [ certPEM ]
}

const getPEMCert = (derBuffer) => {
  return `-----BEGIN CERTIFICATE-----\n${derBuffer.toString('base64').match(/.{0,64}/g).join('\n')}-----END CERTIFICATE-----`
}

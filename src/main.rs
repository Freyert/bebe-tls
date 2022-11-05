use std::{net::TcpStream, io::{Read, Write}};


struct ClientHello {
    protocol_version: [u8;2],
    random: [u8;32],
    legacy_session_id: [u8;32],
    cipher_suites: [u8;2],
    legacy_compression_methods: [u8;1],
    extensions: [u8;8]    
}

impl ClientHello {
    pub fn new() -> Self {
        Self{ 
            protocol_version: [0x03;2],
            random: [0;32], //32 bytes
            legacy_session_id: [0;32], //opaque 0..32
            cipher_suites: [0;2], //CipherSuite (u8,u8) 2..2^16-2
            legacy_compression_methods: [0;1], //opaque 1..2^8-1
            extensions: [0;8] //extension
        }
    }
}

    // Variable-length vectors are defined by specifying a subrange of legal
    // lengths, inclusively, using the notation <floor..ceiling>.  When
    // these are encoded, the actual length precedes the vector's contents
    // in the byte stream.  The length will be in the form of a number
    // consuming as many bytes as required to hold the vector's specified
    // maximum (ceiling) length.  A variable-length vector with an actual
    // length field of zero is referred to as an empty vector.
impl From<ClientHello> for Vec<u8> {
    fn from(hello: ClientHello) -> Self {
        let mut vec: Vec<u8> = Vec::new();
        
        hello.protocol_version.iter().for_each(|b| vec.push(*b));
        hello.random.iter().for_each(|b| vec.push(*b));
        //specify 0 length session_id
        vec.push(0x00);
        vec.push(0x00);
        hello.legacy_session_id.iter().for_each(|b| vec.push(*b));
        //specify a cipher suite. Must be at least 2 bytes
        vec.push(0x00);
        vec.push(0x02);
        hello.cipher_suites.iter().for_each(|b| vec.push(*b));
        vec.push(0x00);
        vec.push(0x01);
        hello.legacy_compression_methods.iter().for_each(|b| vec.push(*b));
        //specify minimum length extensions
        vec.push(0x00);
        vec.push(0x08);
        hello.extensions.iter().for_each(|b| vec.push(*b));
        vec
    }
}

fn main() {
    let mut sock = TcpStream::connect("google.com:443").unwrap();

    let mut buf: [u8; 1024] = [0;1024];


    let hello = ClientHello::new();
    let hello_buff: Vec<u8> = Vec::from(hello);

    sock.write(&hello_buff).unwrap();

    let read = sock.read(buf.as_mut()).unwrap();
    let slice = &buf[0..read];

    println!("{:?}", slice);
}

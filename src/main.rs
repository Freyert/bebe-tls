use std::{net::TcpStream, io::{Read, Write}};


struct ClientHello {
    protocol_version: [u8;2], //[0,1]
    random: [u8;32], //[2,31]
    legacy_session_id: [u8;32],//[35,67]
    cipher_suites: [u8;2], //[68,70]
    legacy_compression_methods: [u8;1],
    extensions: [u8;8]
}

impl IntoIterator for ClientHello {
    type Item = u8;

    type IntoIter = ClientHelloIterator;

    fn into_iter(self) -> Self::IntoIter {
        ClientHelloIterator{_position: 0, msg: self}
    }
}

struct ClientHelloIterator {
    _position: usize,
    msg: ClientHello
}

impl Iterator for ClientHelloIterator {
    type Item = u8;

    //TODO: this doesn't transform the message correctly at all, but I like it better
    //than what was going on before.
    //It needs padding and the ability to handle variable length fields.
    fn next(&mut self) -> Option<Self::Item> {
        let byte = match self._position {
            0..=1 => Some(self.msg.protocol_version[self._position]),
            2..=33 => Some(self.msg.random[self._position -2]),
            34..=65 => Some(self.msg.legacy_session_id[self._position -34]),
            66..=67 => Some(self.msg.cipher_suites[self._position - 66]),
            68 => Some(self.msg.legacy_compression_methods[self._position - 68]),
            69..=76 => Some(self.msg.extensions[self._position-69]),
            _ => None
        };
        self._position += 1;
        return byte
    }
}

impl Read for ClientHelloIterator {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written: usize = 0;
        while written < buf.len() {
            match self.next() {
                Some(byte) => buf[written] = byte,
                None => return Ok(written)
            }
            written += 1
        }
        Ok(written)
    }
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

fn main() {
    let hello = ClientHello::new().into_iter();
    let mut sock = TcpStream::connect("google.com:443").unwrap();


    for x in hello.into_iter() {
        sock.write(&[x]).unwrap();
    }


    let mut buffer = Vec::new();
    sock.read_to_end(&mut buffer).unwrap();

    println!("{:?}", buffer);
}



#[cfg(test)]
mod tests {
    use std::{sync::Arc};

    use crate::ClientHello;

    #[test]
    fn client_hello_iteration() {
        let hello = ClientHello::new();
        let protocol = hello.protocol_version.clone();
        let random = hello.random.clone();
        let legacy_session_id = hello.legacy_session_id.clone();
        let cipher_suites = hello.cipher_suites.clone();
        let legacy_compression_methods = hello.legacy_compression_methods.clone();
        let extensions = hello.extensions.clone();

        let hello_iter = hello.into_iter();
        let mut iter_bytes = Vec::new();

        for byte in hello_iter {
            iter_bytes.push(byte);
        }

        assert_eq!(protocol, iter_bytes[0..=1]);
        assert_eq!(random, iter_bytes[2..=33]);
        assert_eq!(legacy_session_id, iter_bytes[34..=65]);
        assert_eq!(cipher_suites, iter_bytes[66..=67]);
        assert_eq!(legacy_compression_methods, iter_bytes[68..=68]);
        assert_eq!(extensions, iter_bytes[69..])
    }

    #[test]
    fn client_hello_against_rustls() {
        //Build the rustls server configuration
        use rustls_pemfile::{Item, read_one};
        use std::io::{BufReader};


        //A script for generating the test keys lives in "./test",  as well as the cert/key. This filters for just the *.pem files.
        let files: Vec<BufReader<std::fs::File>> = std::fs::read_dir("./test").unwrap().into_iter().map(|dir_entry| dir_entry.as_ref().unwrap().path())
        .filter(|path| path.extension().unwrap() == "pem")
        .map(|file| {
            BufReader::new(
                std::fs::File::open(&file).expect(format!("could not open {:?}", &file.as_os_str()).as_str())
            )
        }).collect();

        println!("{}", files.len());

        //Next we parse the *.pem files to get the cert and key.
        let mut server_cert: Result<Vec<rustls::Certificate>, &'static str> = Err("certificate missing");
        let mut server_key: Result<rustls::PrivateKey, &'static str> = Err("server key missing");
        for mut file in files {
            println!("looping");
            match read_one(&mut file).unwrap() {
                Some(Item::X509Certificate(cert)) => server_cert = Ok(vec!(rustls::Certificate(cert))),
                Some(Item::RSAKey(key)) => server_key = Ok(rustls::PrivateKey(key)),
                Some(Item::PKCS8Key(key)) => server_key = Ok(rustls::PrivateKey(key)),
                _ => ()
            };
        }

        //Configure the TLS server
        let server_config = rustls::ServerConfig::builder().with_safe_defaults();
        let server = server_config.with_no_client_auth().with_single_cert(server_cert.unwrap(), server_key.unwrap()).unwrap();
        let mut server_connection = rustls::ServerConnection::new(Arc::new(server)).unwrap();


        //Here we interact with the server_connection manually.
        //This is great because we don't have to actually open a socket or send packets over the network.
        let mut hello = ClientHello::new().into_iter();
        //First read the TLS packet
        server_connection.read_tls(&mut hello).unwrap();
        //Then process the packet. Will panic if the packet is bad!
        //Great for debugging the client.
        server_connection.process_new_packets().unwrap();
    }
}
using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// communication DNS protocol are carried by "message"
// message is a sequence of bytes
// message contains 5 sections: header, question, answer, authority, additional space

// You can use print statements as follows for debugging, they'll be visible when running tests.
Console.WriteLine("Logs from your program will appear here!");

// Uncomment this block to pass the first stage
// Resolve UDP address
IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
int port = 2053;
IPEndPoint udpEndPoint = new IPEndPoint(ipAddress, port);

// Create UDP socket
UdpClient udpClient = new UdpClient(udpEndPoint);

while (true)
{
    // Receive data
    IPEndPoint sourceEndPoint = new IPEndPoint(IPAddress.Any, 0);
    byte[] receivedData = udpClient.Receive(ref sourceEndPoint);
    string receivedString = Encoding.ASCII.GetString(receivedData);

    // Create an empty response
    byte[] response = new byte[receivedData.Length];

    // Send response
    udpClient.Send(response, response.Length, sourceEndPoint);
}

public class DnsHeaderMessage {
    /// <summary>
    /// package identifier
    /// A random ID assigned to query packets.
    /// Response packets must reply with the same ID.
    /// 16 bits
    /// </summary>
    public ushort ID { get; set; }

    //storage QR, OPCODE, AA, TC, RD
    private ushort _flags1;
    private ushort _flags2;

    /// <summary>
    /// query/response flag
    /// 1 for a reply packet, 0 for a question packet
    /// 1 bit
    /// </summary>
    public bool QR
    {
        // & - bitwise AND
        // bitwise AND checks if the bit is set to 1
        // 1100 & 1010 equals 1000 because only the first bit from the right is 1 in both numbers.
        // 0x8000 is 1000000000000000 in binary
        // != 0 checks if the result of _flags1 & 0x8000 is not zero. 
        // If it is not zero, it means the highest bit of _flags1 is 1, so QR is true. Otherwise, QR is false.
        get => (_flags1 & 0x8000) != 0;
        //0x7FFF in binary is 0111 1111 1111 1111. This mask has all bits set except the highest bit.
        // bit 15 | bit 14 | bit 13 | bit 12 | bit 11 | bit 10 | bit 9 | bit 8 | bit 7 to bit 0
        // QR     | OPCODE (4 bits)                   | AA     | TC    | RD    | Unused (cleared)
        set => _flags1 = (ushort)((_flags1 & 0x7FFF) | (value ? 0x8000 : 0));
    }
    /// <summary>
    /// operation code
    /// 0 for a standard query
    /// Specifies the kind of query in a message.
    /// 4 bits
    /// </summary>
    public byte OPCODE { 
        get; 
        set; 
        }
    /// <summary>
    /// authoritative answer
    /// 1 if the responding server is an authority ("owns") for the domain name in question
    /// 0 if not
    /// 1 bit
    /// </summary>
    public bool AA { get; set; }
    /// <summary>
    /// truncated
    /// 1 if the message was truncated. Longer than 512 bytes.
    /// 0 if not. Always in UDP responses.
    /// 1 bit
    /// </summary>
    public bool TC { get; set; }
    /// <summary>
    /// recursion desired
    /// 1 if the client wants the server to perform recursion
    /// 0 if not
    /// 1 bit
    /// </summary>
    public bool RD { get; set; }
    /// <summary>
    /// recursion available
    /// 1 if the server can perform recursion
    /// 0 if not
    /// 1 bit
    /// </summary>
    public bool RA { get; set; }
    /// <summary>
    /// reserved
    /// Used by DNSSEC. At inception, it was reserved for future use.
    /// 3 bits
    /// </summary>
    public BitArray Z { get; set; } = new BitArray(3);
    /// <summary>
    /// response code
    /// response code indicating the success or failure of the query
    /// 0 for no error
    /// 4 bits
    public BitArray RCODE { get; set; } = new BitArray(4);
    /// <summary>
    /// number of questions
    /// number of questions in the question section of the message
    /// 16 bits
    /// </summary>
    public short QDCOUNT { get; set; }
    /// <summary>
    /// number of answers
    /// number of resource records in the answer section of the message
    /// 16 bits
    /// </summary>
    public short ANCOUNT { get; set; }
    /// <summary>
    /// number of authority resource records
    /// number of resource records in the authority section of the message
    /// 16 bits
    /// </summary>
    public short NSCOUNT { get; set; }
    /// <summary>
    /// number of additional resource records
    /// number of resource records in the additional section of the message
    /// 16 bits
    /// </summary>
    public short ARCOUNT { get; set; }
}


#pragma once
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <map> // used to define the object tree
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

#define BUFF_LEN 512

// We define enumerations as alias for relevant integer values
enum Asn1DataType
{
    INTEGER             = 2,
    OCTET_STRING        = 4,
    OBJECT_IDENTIFIER   = 0x06,
    IpAddress           = 0x40,
    NULL_asn1           = 0x05,
    SEQUENCE            = 0x30,
    Gauge32             = 0x42,
};

enum ErrorStatus
{
    noError     = 0,
    tooBig      = 1,
    noSuchName  = 2,
    badValue    = 3,
    readOnly    = 4,
    genErr      = 5,
};

enum MaxAccess
{
    not_accessible  = 0,
    read_only       = 1,
    read_write      = 2,
};

enum ObjectType
{
    scalar  = 0,
    table   = 1,
    row     = 2,
    column  = 3,
};

/* Definition of the basic data types */
typedef union A {
    int integer_value;   /* for the INTEGER type */
    char* char_array_value; /* for OCTET STRING, OBJECT IDENTIFIER, IpAddress */
} tvalue;

typedef struct B {
    ObjectType object_type = ObjectType::scalar;
    Asn1DataType data_type;
    MaxAccess max_access = MaxAccess::not_accessible;
    unsigned int length;
    tvalue value;
} TypeMyNode;

typedef std::map<std::string, TypeMyNode> TypeMyTree; // a tree to store the managed objects

// variable binding
typedef struct {
    std::string oid;
    int length;
    int asn1_type;
    tvalue value;
} VariableBind;

// Forward declarations of helper functions
char int2byte(unsigned int number);
unsigned int byte2int(unsigned char bb);

// TLV helping functions - decoding functions
int read_tlv_int(char *data, int &read_value);
int read_tlv_string(char *data, char *read_value);
int read_tlv_oid(char *data, std::string &oid);
int read_tlv_variable_binding(char *data, VariableBind &tmpVarBind);
int read_tlv_variable_binding_list(char *data, std::vector<VariableBind> &var_bind_list);

// Encoding functions
unsigned int int_to_tlv(char *ber_coding, unsigned int value);
unsigned int char_array_to_tlv(char *ber_coding, const char *char_array, unsigned int value_length, Asn1DataType type = Asn1DataType::OCTET_STRING);
unsigned int string_to_tlv(char *ber_coding, std::string str);
unsigned int oid_to_tlv(char *ber_coding, std::string oid);
unsigned int varbind_to_tlv(char *ber_coding, VariableBind tmpVarBind);
// Add this to your header file
std::string parse_oid(char* data, int length);

class SNMP_message
{
private:
    void error_reading_packet() {
        std::cout << "Error reading packet\n";
        this->valid_paket = 0;
    }

public:
    int valid_paket;
    int version;
    std::string comunity;
    enum PduType { GET_REQUEST = (0xA0), GET_NEXT_REQUEST = (0xA1), GET_RESPONSE = (0xA2), SET_REQUEST = (0xA3) };
    PduType pdu_type;
    int request_id;
    ErrorStatus error_status;
    int error_index;
    std::vector<VariableBind> variable_binding_list;

    // Default constructor
    SNMP_message() {
        valid_paket = 1;
        version = 0;
        comunity = "public";
        pdu_type = PduType::GET_RESPONSE;
        request_id = 0;
        error_status = ErrorStatus::noError;
        error_index = 0;
    }

    // Constructor that decodes from BER encoded data
    SNMP_message(char* data);

    // Function to encode the SNMP message into BER format
    int to_tlv(char* ber_msg_buffer, int buffer_length);

    // Helper functions for encoding components of the message
    unsigned int varbind_to_tlv(char *ber_coding, VariableBind tmpVarBind);
    unsigned int oid_to_tlv(char *ber_coding, std::string oid);
    unsigned int char_array_to_tlv(char *ber_coding, const char *char_array, unsigned int value_length, Asn1DataType type);
    unsigned int int_to_tlv(char *ber_coding, unsigned int value);
};

// Implementation of helper functions

inline char int2byte(unsigned int number) {
    return static_cast<char>(number & 0xFF);
}

inline unsigned int byte2int(unsigned char bb) {
    return static_cast<unsigned int>(bb);
}

// TLV decoding functions
inline int read_tlv_int(char *data, int &read_value) {
    if (data == nullptr) return 0;

    // Check if type is INTEGER
    if (byte2int(data[0]) != INTEGER) return 0;

    // Get length
    int length = byte2int(data[1]);

    // Extract value
    read_value = 0;
    for (int i = 0; i < length; i++) {
        read_value = (read_value << 8) | byte2int(data[2 + i]);
    }

    return 2 + length; // Return total bytes consumed
}

inline int read_tlv_string(char *data, char *read_value) {
    if (data == nullptr || read_value == nullptr) return 0;

    // Check if type is OCTET_STRING
    if (byte2int(data[0]) != OCTET_STRING) return 0;

    // Get length
    int length = byte2int(data[1]);

    // Copy string value
    memcpy(read_value, data + 2, length);
    read_value[length] = '\0'; // Null terminate

    return 2 + length; // Return total bytes consumed
}

inline int read_tlv_oid(char *data, std::string &oid) {
    if (data == nullptr) return 0;

    // Check if type is OBJECT_IDENTIFIER
    if (byte2int(data[0]) != OBJECT_IDENTIFIER) return 0;

    // Get length
    int length = byte2int(data[1]);

    // Extract first two components (encoded as 40*X+Y)
    int first_byte = byte2int(data[2]);
    int first_component = first_byte / 40;
    int second_component = first_byte % 40;

    std::ostringstream oss;
    oss << first_component << "." << second_component;

    // Extract remaining components
    int offset = 3;
    while (offset < 2 + length) {
        unsigned int value = 0;
        unsigned char byte;

        // Handle multi-byte encoding
        do {
            byte = data[offset++];
            value = (value << 7) | (byte & 0x7F);
        } while ((byte & 0x80) && offset < 2 + length);

        oss << "." << value;
    }

    oid = oss.str();
    return 2 + length; // Return total bytes consumed
}

inline int read_tlv_variable_binding(char *data, VariableBind &tmpVarBind) {
    if (data == nullptr) return 0;

    // Check if type is SEQUENCE
    if (byte2int(data[0]) != SEQUENCE) return 0;

    // Get sequence length
    int seq_length = byte2int(data[1]);
    int offset = 2;

    // Read OID
    std::string oid;
    int oid_bytes = read_tlv_oid(data + offset, oid);
    if (oid_bytes == 0) return 0;
    tmpVarBind.oid = oid;
    offset += oid_bytes;

    // Read value - type, length, and value
    int value_type = byte2int(data[offset]);
    tmpVarBind.asn1_type = value_type;
    int value_length = byte2int(data[offset + 1]);
    tmpVarBind.length = value_length;
    offset += 2;

    // Handle different types
    switch (value_type) {
        case INTEGER:
            {
                int int_value;
                read_tlv_int(data + offset - 2, int_value); // -2 to include type and length
                tmpVarBind.value.integer_value = int_value;
            }
            break;

        case OCTET_STRING:
        case IpAddress:
            {
                char* str_value = new char[value_length + 1];
                memcpy(str_value, data + offset, value_length);
                str_value[value_length] = '\0';
                tmpVarBind.value.char_array_value = str_value;
            }
            break;

        case NULL_asn1:
            // Nothing to copy for NULL
            break;

        default:
            std::cout << "Unsupported value type: " << value_type << std::endl;
            return 0;
    }

    offset += value_length;
    return offset; // Return total bytes consumed
}

inline int read_tlv_variable_binding_list(char *data, std::vector<VariableBind> &var_bind_list) {
    if (data == nullptr) return 0;

    // Check if type is SEQUENCE
    if (byte2int(data[0]) != SEQUENCE) return 0;

    // Get sequence length
    int seq_length = byte2int(data[1]);
    int offset = 2;
    int end_offset = offset + seq_length;

    // Clear existing bindings
    var_bind_list.clear();

    // Read variable bindings
    while (offset < end_offset) {
        VariableBind tmpVarBind;
        int varbind_bytes = read_tlv_variable_binding(data + offset, tmpVarBind);
        if (varbind_bytes == 0) return 0;

        var_bind_list.push_back(tmpVarBind);
        offset += varbind_bytes;
    }

    return offset; // Return total bytes consumed
}
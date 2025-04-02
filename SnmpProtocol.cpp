#include "SnmpProtocol.h"

SNMP_message::SNMP_message(char* data) {
    // Initialize defaults
    valid_paket = 1;
    version = 0;
    comunity = "public";
    pdu_type = PduType::GET_RESPONSE;
    request_id = 0;
    error_status = ErrorStatus::noError;
    error_index = 0;

    if (data == nullptr) {
        error_reading_packet();
        return;
    }

    int offset = 0;

    // Check if packet starts with SEQUENCE
    if (byte2int(data[offset]) != SEQUENCE) {
        error_reading_packet();
        return;
    }
    offset++; // Skip SEQUENCE tag

    // Get packet length
    int packet_length = byte2int(data[offset]);
    offset++;

    // Read version
    int version_bytes = read_tlv_int(data + offset, version);
    if (version_bytes == 0) {
        error_reading_packet();
        return;
    }
    offset += version_bytes;

    // Read community string
    int community_type = byte2int(data[offset]);
    if (community_type != OCTET_STRING) {
        error_reading_packet();
        return;
    }

    int community_length = byte2int(data[offset + 1]);
    offset += 2; // Skip type and length

    char* community_str = new char[community_length + 1];
    memcpy(community_str, data + offset, community_length);
    community_str[community_length] = '\0';
    comunity = std::string(community_str);
    delete[] community_str;

    offset += community_length;

    // Read PDU type
    pdu_type = static_cast<PduType>(byte2int(data[offset]));
    offset++;

    // Skip PDU length
    int pdu_length = byte2int(data[offset]);
    offset++;

    // Read request ID
    int request_id_bytes = read_tlv_int(data + offset, request_id);
    if (request_id_bytes == 0) {
        error_reading_packet();
        return;
    }
    offset += request_id_bytes;

    // Read error status
    int error_status_value;
    int error_status_bytes = read_tlv_int(data + offset, error_status_value);
    if (error_status_bytes == 0) {
        error_reading_packet();
        return;
    }
    error_status = static_cast<ErrorStatus>(error_status_value);
    offset += error_status_bytes;

    // Read error index
    int error_index_bytes = read_tlv_int(data + offset, error_index);
    if (error_index_bytes == 0) {
        error_reading_packet();
        return;
    }
    offset += error_index_bytes;

    // Read variable binding list
    int varbind_list_bytes = read_tlv_variable_binding_list(data + offset, variable_binding_list);
    if (varbind_list_bytes == 0) {
        error_reading_packet();
        return;
    }
}

// Implementation of to_tlv function that was already declared in header
int SNMP_message::to_tlv(char* ber_msg_buffer, int buffer_length) {
    if (!valid_paket || ber_msg_buffer == nullptr || buffer_length <= 0) {
        return 0;
    }

    int offset = 0;
    int length_offset = 0;
    int total_length = 0;
    char temp_buffer[BUFF_LEN];

    // Start with the SEQUENCE tag
    ber_msg_buffer[offset++] = SEQUENCE;
    length_offset = offset++; // Save position for length

    // Version
    int version_length = int_to_tlv(temp_buffer, version);
    if (offset + version_length >= buffer_length) return 0;
    memcpy(ber_msg_buffer + offset, temp_buffer, version_length);
    offset += version_length;
    total_length += version_length;

    // Community string
    int community_length = char_array_to_tlv(temp_buffer, comunity.c_str(), comunity.length(), Asn1DataType::OCTET_STRING);
    if (offset + community_length >= buffer_length) return 0;
    memcpy(ber_msg_buffer + offset, temp_buffer, community_length);
    offset += community_length;
    total_length += community_length;

    // PDU type
    ber_msg_buffer[offset++] = static_cast<char>(pdu_type);
    int pdu_length_offset = offset++; // Save position for PDU length
    int pdu_total_length = 0;

    // Request ID
    int request_id_length = int_to_tlv(temp_buffer, request_id);
    if (offset + request_id_length >= buffer_length) return 0;
    memcpy(ber_msg_buffer + offset, temp_buffer, request_id_length);
    offset += request_id_length;
    pdu_total_length += request_id_length;

    // Error status
    int error_status_length = int_to_tlv(temp_buffer, static_cast<int>(error_status));
    if (offset + error_status_length >= buffer_length) return 0;
    memcpy(ber_msg_buffer + offset, temp_buffer, error_status_length);
    offset += error_status_length;
    pdu_total_length += error_status_length;

    // Error index
    int error_index_length = int_to_tlv(temp_buffer, error_index);
    if (offset + error_index_length >= buffer_length) return 0;
    memcpy(ber_msg_buffer + offset, temp_buffer, error_index_length);
    offset += error_index_length;
    pdu_total_length += error_index_length;

    // Variable bindings list - starts with SEQUENCE
    ber_msg_buffer[offset++] = SEQUENCE;
    int varbind_list_length_offset = offset++; // Save position for length
    int varbind_list_total_length = 0;

    // Add each variable binding
    for (const auto& varbind : variable_binding_list) {
        int varbind_length = varbind_to_tlv(temp_buffer, varbind);
        if (varbind_length <= 0 || offset + varbind_length >= buffer_length) {
            std::cout << "Failed to encode variable binding or buffer too small" << std::endl;
            return 0;
        }
        memcpy(ber_msg_buffer + offset, temp_buffer, varbind_length);
        offset += varbind_length;
        varbind_list_total_length += varbind_length;
    }

    // Fill in varbind list length
    ber_msg_buffer[varbind_list_length_offset] = static_cast<char>(varbind_list_total_length);
    pdu_total_length += 2 + varbind_list_total_length; // 2 bytes for SEQUENCE + length

    // Fill in PDU length
    ber_msg_buffer[pdu_length_offset] = static_cast<char>(pdu_total_length);
    total_length += 2 + pdu_total_length; // 2 bytes for PDU type + length

    // Fill in total message length
    ber_msg_buffer[length_offset] = static_cast<char>(total_length);

    return offset; // Total bytes written
}

// Implementation of helper functions for SNMP_message class
unsigned int SNMP_message::varbind_to_tlv(char *ber_coding, VariableBind tmpVarBind) {
    int offset = 0;
    int length_offset = 0;
    int total_length = 0;
    char temp_buffer[BUFF_LEN];

    // Start with SEQUENCE for the variable binding
    ber_coding[offset++] = SEQUENCE;
    length_offset = offset++; // Save position for length

    // OID
    int oid_length = oid_to_tlv(temp_buffer, tmpVarBind.oid);
    if (oid_length <= 0) return 0;
    memcpy(ber_coding + offset, temp_buffer, oid_length);
    offset += oid_length;
    total_length += oid_length;

    // Value based on ASN.1 type
    switch (tmpVarBind.asn1_type) {
        case Asn1DataType::INTEGER:
            {
                int int_length = int_to_tlv(temp_buffer, tmpVarBind.value.integer_value);
                memcpy(ber_coding + offset, temp_buffer, int_length);
                offset += int_length;
                total_length += int_length;
            }
            break;

        case Asn1DataType::OCTET_STRING:
        case Asn1DataType::IpAddress:
            {
                int str_length = char_array_to_tlv(temp_buffer, tmpVarBind.value.char_array_value,
                                                  tmpVarBind.length,
                                                  static_cast<Asn1DataType>(tmpVarBind.asn1_type));
                memcpy(ber_coding + offset, temp_buffer, str_length);
                offset += str_length;
                total_length += str_length;
            }
            break;

        case Asn1DataType::NULL_asn1:
            ber_coding[offset++] = NULL_asn1;
            ber_coding[offset++] = 0; // Length of NULL is 0
            total_length += 2;
            break;

        default:
            std::cout << "Unsupported ASN.1 type: " << tmpVarBind.asn1_type << std::endl;
            return 0;
    }

    // Fill in varbind length
    ber_coding[length_offset] = static_cast<char>(total_length);

    return offset; // Total bytes written
}

unsigned int SNMP_message::oid_to_tlv(char *ber_coding, std::string oid) {
    if (oid.empty()) return 0;

    ber_coding[0] = OBJECT_IDENTIFIER;

    // Parse OID
    std::vector<int> oid_components;
    std::istringstream ss(oid);
    std::string component;

    while (std::getline(ss, component, '.')) {
        if (!component.empty()) {
            oid_components.push_back(std::stoi(component));
        }
    }

    if (oid_components.size() < 2) return 0;

    // First two components are encoded as 40*X+Y
    int first_byte = 40 * oid_components[0] + oid_components[1];

    // Encode length - this is a simplification; for large OIDs, you need proper BER length encoding
    int oid_value_length = 1; // Start with the first combined byte

    // Count additional bytes needed for components 3+
    for (size_t i = 2; i < oid_components.size(); i++) {
        int val = oid_components[i];
        if (val < 128) oid_value_length += 1;
        else if (val < 16384) oid_value_length += 2;
        else oid_value_length += 3; // Simplified; could be more for very large values
    }

    ber_coding[1] = static_cast<char>(oid_value_length);

    // Encode first byte
    ber_coding[2] = static_cast<char>(first_byte);

    // Encode remaining components
    int offset = 3;
    for (size_t i = 2; i < oid_components.size(); i++) {
        int val = oid_components[i];

        // Simplified encoding for values < 128
        if (val < 128) {
            ber_coding[offset++] = static_cast<char>(val);
        }
        // For larger values, use multi-byte encoding (each byte except last has high bit set)
        else if (val < 16384) {
            ber_coding[offset++] = static_cast<char>((val >> 7) | 0x80);
            ber_coding[offset++] = static_cast<char>(val & 0x7F);
        }
        else {
            // Add more cases for larger values if needed
            ber_coding[offset++] = static_cast<char>((val >> 14) | 0x80);
            ber_coding[offset++] = static_cast<char>(((val >> 7) & 0x7F) | 0x80);
            ber_coding[offset++] = static_cast<char>(val & 0x7F);
        }
    }

    return offset;
}

unsigned int SNMP_message::char_array_to_tlv(char *ber_coding, const char *char_array, unsigned int value_length, Asn1DataType type) {
    if (char_array == nullptr) return 0;

    ber_coding[0] = static_cast<char>(type);
    ber_coding[1] = static_cast<char>(value_length); // Simplified; for large values, need proper length encoding

    memcpy(ber_coding + 2, char_array, value_length);

    return 2 + value_length;
}

unsigned int SNMP_message::int_to_tlv(char *ber_coding, unsigned int value) {
    ber_coding[0] = INTEGER;

    // Determine how many bytes are needed to represent the value
    int num_bytes = 0;
    unsigned int temp = value;

    // Handle zero specially
    if (value == 0) {
        ber_coding[1] = 1; // Length
        ber_coding[2] = 0; // Value
        return 3;
    }

    // Check if the value is negative (sign bit is set)
    bool is_negative = (value & 0x80000000) != 0;

    // Count bytes needed
    do {
        num_bytes++;
        temp >>= 8;
    } while (temp > 0);

    // Additional byte might be needed for sign extension
    if (is_negative && (value & 0x800000) == 0) {
        num_bytes++;
    }

    ber_coding[1] = static_cast<char>(num_bytes); // Length

    // Write the value in big-endian format
    for (int i = 0; i < num_bytes; i++) {
        ber_coding[2 + i] = static_cast<char>((value >> ((num_bytes - 1 - i) * 8)) & 0xFF);
    }

    return 2 + num_bytes;
}

// Implementation of global encoding functions
unsigned int int_to_tlv(char *ber_coding, unsigned int value) {
    ber_coding[0] = INTEGER;

    // Determine how many bytes are needed to represent the value
    int num_bytes = 0;
    unsigned int temp = value;

    // Handle zero specially
    if (value == 0) {
        ber_coding[1] = 1; // Length
        ber_coding[2] = 0; // Value
        return 3;
    }

    // Check if the value is negative (sign bit is set)
    bool is_negative = (value & 0x80000000) != 0;

    // Count bytes needed
    do {
        num_bytes++;
        temp >>= 8;
    } while (temp > 0);

    // Additional byte might be needed for sign extension
    if (is_negative && (value & 0x800000) == 0) {
        num_bytes++;
    }

    ber_coding[1] = static_cast<char>(num_bytes); // Length

    // Write the value in big-endian format
    for (int i = 0; i < num_bytes; i++) {
        ber_coding[2 + i] = static_cast<char>((value >> ((num_bytes - 1 - i) * 8)) & 0xFF);
    }

    return 2 + num_bytes;
}

unsigned int char_array_to_tlv(char *ber_coding, const char *char_array, unsigned int value_length, Asn1DataType type) {
    if (char_array == nullptr) return 0;

    ber_coding[0] = static_cast<char>(type);
    ber_coding[1] = static_cast<char>(value_length); // Simplified; for large values, need proper length encoding

    memcpy(ber_coding + 2, char_array, value_length);

    return 2 + value_length;
}

unsigned int string_to_tlv(char *ber_coding, std::string str) {
    return char_array_to_tlv(ber_coding, str.c_str(), str.length(), Asn1DataType::OCTET_STRING);
}

unsigned int oid_to_tlv(char *ber_coding, std::string oid) {
    if (oid.empty()) return 0;

    ber_coding[0] = OBJECT_IDENTIFIER;

    // Parse OID
    std::vector<int> oid_components;
    std::istringstream ss(oid);
    std::string component;

    while (std::getline(ss, component, '.')) {
        if (!component.empty()) {
            oid_components.push_back(std::stoi(component));
        }
    }

    if (oid_components.size() < 2) return 0;

    // First two components are encoded as 40*X+Y
    int first_byte = 40 * oid_components[0] + oid_components[1];

    // Encode length - this is a simplification; for large OIDs, you need proper BER length encoding
    int oid_value_length = 1; // Start with the first combined byte

    // Count additional bytes needed for components 3+
    for (size_t i = 2; i < oid_components.size(); i++) {
        int val = oid_components[i];
        if (val < 128) oid_value_length += 1;
        else if (val < 16384) oid_value_length += 2;
        else oid_value_length += 3; // Simplified; could be more for very large values
    }

    ber_coding[1] = static_cast<char>(oid_value_length);

    // Encode first byte
    ber_coding[2] = static_cast<char>(first_byte);

    // Encode remaining components
    int offset = 3;
    for (size_t i = 2; i < oid_components.size(); i++) {
        int val = oid_components[i];

        // Simplified encoding for values < 128
        if (val < 128) {
            ber_coding[offset++] = static_cast<char>(val);
        }
        // For larger values, use multi-byte encoding (each byte except last has high bit set)
        else if (val < 16384) {
            ber_coding[offset++] = static_cast<char>((val >> 7) | 0x80);
            ber_coding[offset++] = static_cast<char>(val & 0x7F);
        }
        else {
            // Add more cases for larger values if needed
            ber_coding[offset++] = static_cast<char>((val >> 14) | 0x80);
            ber_coding[offset++] = static_cast<char>(((val >> 7) & 0x7F) | 0x80);
            ber_coding[offset++] = static_cast<char>(val & 0x7F);
        }
    }

    return offset;
}

unsigned int varbind_to_tlv(char *ber_coding, VariableBind tmpVarBind) {
    int offset = 0;
    int length_offset = 0;
    int total_length = 0;
    char temp_buffer[BUFF_LEN];

    // Start with SEQUENCE for the variable binding
    ber_coding[offset++] = SEQUENCE;
    length_offset = offset++; // Save position for length

    // OID
    int oid_length = oid_to_tlv(temp_buffer, tmpVarBind.oid);
    if (oid_length <= 0) return 0;
    memcpy(ber_coding + offset, temp_buffer, oid_length);
    offset += oid_length;
    total_length += oid_length;

    // Value based on ASN.1 type
    switch (tmpVarBind.asn1_type) {
        case Asn1DataType::INTEGER:
            {
                int int_length = int_to_tlv(temp_buffer, tmpVarBind.value.integer_value);
                memcpy(ber_coding + offset, temp_buffer, int_length);
                offset += int_length;
                total_length += int_length;
            }
            break;

        case Asn1DataType::OCTET_STRING:
        case Asn1DataType::IpAddress:
            {
                int str_length = char_array_to_tlv(temp_buffer, tmpVarBind.value.char_array_value,
                                                  tmpVarBind.length,
                                                  static_cast<Asn1DataType>(tmpVarBind.asn1_type));
                memcpy(ber_coding + offset, temp_buffer, str_length);
                offset += str_length;
                total_length += str_length;
            }
            break;

        case Asn1DataType::NULL_asn1:
            ber_coding[offset++] = NULL_asn1;
            ber_coding[offset++] = 0; // Length of NULL is 0
            total_length += 2;
            break;

        default:
            std::cout << "Unsupported ASN.1 type: " << tmpVarBind.asn1_type << std::endl;
            return 0;
    }

    // Fill in varbind length
    ber_coding[length_offset] = static_cast<char>(total_length);

    return offset; // Total bytes written
}

// Helper function to convert byte to int
int byte2int(char byte) {
    return static_cast<unsigned char>(byte);
}



// Keep this function since it wasn't already defined
std::string parse_oid(char* data, int length) {
    if (length <= 0) return "";

    std::stringstream oid;

    // First byte encodes first two OID components (X.Y as 40*X+Y)
    unsigned char first_byte = byte2int(data[0]);
    int first = first_byte / 40;
    int second = first_byte % 40;

    oid << first << "." << second;

    // Process remaining components
    int i = 1;
    while (i < length) {
        unsigned int component = 0;

        // Handle multi-byte components (high bit set on all but last byte)
        while (i < length && (byte2int(data[i]) & 0x80)) {
            component = (component << 7) | (byte2int(data[i]) & 0x7F);
            i++;
        }

        // Last byte of component (high bit not set)
        if (i < length) {
            component = (component << 7) | byte2int(data[i]);
            i++;
        }

        oid << "." << component;
    }

    return oid.str();
}




#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include "SnmpProtocol.h"

// SNMP
#define SNMP_MSG_MAX_LEN 2048

// Listening Port
#define PORT 1025

// Define the SOCKET type
typedef int SOCKET;

// Security System MIB OIDs
#define OID_PEOPLE_ENTERED"1.3.6.1.2.1.50.1.1.0"
#define OID_PEOPLE_LEFT   "1.3.6.1.2.1.50.1.2.0"
#define OID_DEVICE_IP     "1.3.6.1.2.1.50.1.3.0"
#define OID_HISTORY_TABLE "1.3.6.1.2.1.50.1.4.0"
#define OID_HISTORY_ENTRY "1.3.6.1.2.1.50.1.4.1.0"
#define OID_DAY_OF_YEAR   "1.3.6.1.2.1.50.1.4.1.1"
#define OID_DAILY_ENTERED "1.3.6.1.2.1.50.1.4.1.2"
#define OID_DAILY_LEFT    "1.3.6.1.3.1.50.1.4.1.3"

// Global variables to store managed objects
int g_peopleEntered = 0;
int g_peopleLeft = 0;
char g_deviceIP[16] = "192.168.1.100";

// Structure for history table entry
typedef struct {
    int dayOfYear;
    int peopleEntered;
    int peopleLeft;
} HistoryEntry;

std::vector<HistoryEntry> g_historyTable = {
    {1, 100, 50},    // Sample entries for testing
};


void printAsHexa(char* byteArray, ssize_t lengthArray) {
    unsigned int value;
    for (int i = 0; i < lengthArray; i++) {
        value = byte2int(byteArray[i]);
        std::cout << std::hex << std::uppercase << "0x" << std::setw(2) << std::setfill('0') << value << " " << std::dec;
    }
    std::cout << std::endl;
}

int startSocket(SOCKET& sd, int puerto) {
    /* Open a datagram socket */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd == -1) {
        std::cerr << "Could not create socket" << std::endl;
        return -1;
    }

    //Prepare the sockaddr_in structure
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(puerto);

    //Bind
    if (bind(sd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return -1;
    }
    std::cout << "Bind done to socket " << sd << std::endl;
    return 0;
}

int receiveFromSocket(SOCKET sd, char* received, ssize_t& recv_len, struct sockaddr_in& infoIpCliente) {
    socklen_t clientLength = sizeof(infoIpCliente);

    std::cout << "Waiting for data..." << std::endl;
    //clear the buffer by filling null, it might have previously received data
    memset(received, '\0', SNMP_MSG_MAX_LEN);

    //try to receive some data, this is a blocking call
    recv_len = recvfrom(sd, received, SNMP_MSG_MAX_LEN, 0, (struct sockaddr*)&infoIpCliente, &clientLength);

    if (recv_len < 1) {
        std::cerr << "recvfrom() failed" << std::endl;
        exit(EXIT_FAILURE);
    }
    return 0;
}

int sendToSocket(SOCKET sd, const char* mensaje, ssize_t longMensaje, struct sockaddr_in& infoIpDestino) {
    int infoIpLength = sizeof(infoIpDestino);
    ssize_t sentBytes;
    sentBytes = sendto(sd, mensaje, longMensaje, 0, (struct sockaddr*)&infoIpDestino, infoIpLength);
    std::cout << "Sent " << sentBytes << " bytes" << std::endl;
    return 0;
}

// Normalize OID to ensure consistent format
std::string normalizeOid(const std::string& oid) {
    std::vector<std::string> parts;
    std::istringstream ss(oid);
    std::string part;

    // Split by dots
    while (std::getline(ss, part, '.')) {
        parts.push_back(part);
    }

    // Handle the first component specially
    if (!parts.empty()) {
        // In SNMP, first two nodes are encoded in a single byte
        // 43 = 1*40+3 represents iso(1).org(3)
        if (parts[0] == "43") {
            std::vector<std::string> newParts;
            newParts.push_back("1");
            newParts.push_back("3");

            // Add the rest of the parts
            for (size_t i = 1; i < parts.size(); i++) {
                newParts.push_back(parts[i]);
            }

            parts = newParts;
        }
    }

    // Reconstruct the OID
    std::string normalized;
    for (size_t i = 0; i < parts.size(); i++) {
        normalized += parts[i];
        if (i < parts.size() - 1) {
            normalized += ".";
        }
    }

    std::cout << "Original OID: " << oid << " -> Normalized: " << normalized << std::endl;
    return normalized;
}

void initializeManagementDB(TypeMyTree& management_db) {
    // People Entered
    TypeMyNode n_peopleEntered;
    n_peopleEntered.object_type = ObjectType::scalar;
    n_peopleEntered.data_type = Asn1DataType::INTEGER;
    n_peopleEntered.max_access = MaxAccess::read_write;
    n_peopleEntered.length = sizeof(int);
    n_peopleEntered.value.integer_value = g_peopleEntered;

    std::cout << "Adding OID: " << OID_PEOPLE_ENTERED << std::endl;
    management_db[std::string(OID_PEOPLE_ENTERED)] = n_peopleEntered;

    // People Left
    TypeMyNode n_peopleLeft;
    n_peopleLeft.object_type = ObjectType::scalar;
    n_peopleLeft.data_type = Asn1DataType::INTEGER;
    n_peopleLeft.max_access = MaxAccess::read_write;
    n_peopleLeft.length = sizeof(int);
    n_peopleLeft.value.integer_value = g_peopleLeft;

    std::cout << "Adding OID: " << OID_PEOPLE_LEFT << std::endl;
    management_db[std::string(OID_PEOPLE_LEFT)] = n_peopleLeft;

    // Device IP Address
    TypeMyNode n_deviceIP;
    n_deviceIP.object_type = ObjectType::scalar;
    n_deviceIP.data_type = Asn1DataType::IpAddress;
    n_deviceIP.max_access = MaxAccess::read_write;
    n_deviceIP.length = strlen(g_deviceIP);
    n_deviceIP.value.char_array_value = g_deviceIP;

    std::cout << "Adding OID: " << OID_DEVICE_IP << std::endl;
    management_db[std::string(OID_DEVICE_IP)] = n_deviceIP;

    // History Table
    TypeMyNode n_historyTable;
    n_historyTable.object_type = ObjectType::table;
    n_historyTable.data_type = Asn1DataType::NULL_asn1;
    n_historyTable.max_access = MaxAccess::read_only;
    std::cout << "Adding OID: " << OID_HISTORY_TABLE << std::endl;
    management_db[std::string(OID_HISTORY_TABLE)] = n_historyTable;

    // History Entry
    TypeMyNode n_historyEntry;
    n_historyEntry.object_type = ObjectType::table;
    n_historyEntry.data_type = Asn1DataType::NULL_asn1;
    n_historyEntry.max_access = MaxAccess::read_only;
    std::cout << "Adding OID: " << OID_HISTORY_ENTRY << std::endl;
    management_db[std::string(OID_HISTORY_ENTRY)] = n_historyEntry;

    // Column definitions - these are crucial additions
    // Day of Year Column
    TypeMyNode n_dayOfYearColumn;
    n_dayOfYearColumn.object_type = ObjectType::column;
    n_dayOfYearColumn.data_type = Asn1DataType::INTEGER;
    n_dayOfYearColumn.max_access = MaxAccess::read_write;
    std::cout << "Adding OID: " << OID_DAY_OF_YEAR << std::endl;
    management_db[std::string(OID_DAY_OF_YEAR)] = n_dayOfYearColumn;

    // Daily Entered Column
    TypeMyNode n_dailyEnteredColumn;
    n_dailyEnteredColumn.object_type = ObjectType::column;
    n_dailyEnteredColumn.data_type = Asn1DataType::INTEGER;
    n_dailyEnteredColumn.max_access = MaxAccess::read_write;
    std::cout << "Adding OID: " << OID_DAILY_ENTERED << std::endl;
    management_db[std::string(OID_DAILY_ENTERED)] = n_dailyEnteredColumn;

    // Daily Left Column
    TypeMyNode n_dailyLeftColumn;
    n_dailyLeftColumn.object_type = ObjectType::column;
    n_dailyLeftColumn.data_type = Asn1DataType::INTEGER;
    n_dailyLeftColumn.max_access = MaxAccess::read_write;
    std::cout << "Adding OID: " << OID_DAILY_LEFT << std::endl;
    management_db[std::string(OID_DAILY_LEFT)] = n_dailyLeftColumn;

    // Add history entries (instances)
    for (size_t i = 0; i < g_historyTable.size(); ++i) {
        // Index for this entry (1-based)
        std::string index = std::to_string(i+1);

        // Day of Year Entry
        std::string dayOid = std::string(OID_DAY_OF_YEAR) + "." + index;
        TypeMyNode n_dayOfYear;
        n_dayOfYear.object_type = ObjectType::scalar;
        n_dayOfYear.data_type = Asn1DataType::INTEGER;
        n_dayOfYear.max_access = MaxAccess::read_write;
        n_dayOfYear.length = sizeof(int);
        n_dayOfYear.value.integer_value = g_historyTable[i].dayOfYear;
        std::cout << "Adding OID: " << dayOid << std::endl;
        management_db[dayOid] = n_dayOfYear;

        // Daily Entered Entry
        std::string enteredOid = std::string(OID_DAILY_ENTERED) + "." + index;
        TypeMyNode n_dailyEntered;
        n_dailyEntered.object_type = ObjectType::scalar;
        n_dailyEntered.data_type = Asn1DataType::INTEGER;
        n_dailyEntered.max_access = MaxAccess::read_write;
        n_dailyEntered.length = sizeof(int);
        n_dailyEntered.value.integer_value = g_historyTable[i].peopleEntered;
        std::cout << "Adding OID: " << enteredOid << std::endl;
        management_db[enteredOid] = n_dailyEntered;

        // Daily Left Entry
        std::string leftOid = std::string(OID_DAILY_LEFT) + "." + index;
        TypeMyNode n_dailyLeft;
        n_dailyLeft.object_type = ObjectType::scalar;
        n_dailyLeft.data_type = Asn1DataType::INTEGER;
        n_dailyLeft.max_access = MaxAccess::read_write;
        n_dailyLeft.length = sizeof(int);
        n_dailyLeft.value.integer_value = g_historyTable[i].peopleLeft;
        std::cout << "Adding OID: " << leftOid << std::endl;
        management_db[leftOid] = n_dailyLeft;
    }

    // Print all OIDs in the database for debugging
    std::cout << "=== REGISTERED OIDs ===" << std::endl;
    for (const auto& item : management_db) {
        std::cout << "OID: " << item.first << std::endl;
    }
    std::cout << "======================" << std::endl;
}
void processGetRequest(SNMP_message* request, SNMP_message* response, TypeMyTree& management_db) {
    response->pdu_type = SNMP_message::PduType::GET_RESPONSE;
    response->request_id = request->request_id;
    response->error_status = noError;
    response->error_index = 0;
    response->variable_binding_list.clear();

    // Process each variable binding in the request
    for (size_t i = 0; i < request->variable_binding_list.size(); i++) {
        VariableBind requestVarBind = request->variable_binding_list[i];
        VariableBind responseVarBind;
        responseVarBind.oid = requestVarBind.oid;

        // Normalize the OID to fix the issue
        std::string normalizedOid = normalizeOid(requestVarBind.oid);

        std::cout << "GET request for OID: " << requestVarBind.oid << std::endl;
        std::cout << "Normalized OID: " << normalizedOid << std::endl;

        // Check if the OID exists in our management database
        auto it = management_db.find(normalizedOid);
        if (it != management_db.end()) {
            std::cout << "OID found in management_db" << std::endl;

            // Check if this is a column without an instance
            if (it->second.object_type == ObjectType::column) {
                std::cout << "This is a column OID without an instance - error" << std::endl;
                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                responseVarBind.length = 0;
                response->error_status = noSuchName;
                response->error_index = i + 1;
            } else {
                // OID found, copy the value
                responseVarBind.asn1_type = it->second.data_type;
                responseVarBind.length = it->second.length;

                // Handle different data types
                switch (it->second.data_type) {
                    case Asn1DataType::INTEGER:
                        responseVarBind.value.integer_value = it->second.value.integer_value;
                        std::cout << "Integer value: " << responseVarBind.value.integer_value << std::endl;
                        break;
                    case Asn1DataType::OCTET_STRING:
                    case Asn1DataType::IpAddress:
                        if (it->second.value.char_array_value != nullptr) {
                            responseVarBind.value.char_array_value = it->second.value.char_array_value;
                            std::cout << "String/IP value: " << responseVarBind.value.char_array_value << std::endl;
                        } else {
                            responseVarBind.value.char_array_value = nullptr;
                            std::cout << "String/IP value is null" << std::endl;
                        }
                        break;
                    case Asn1DataType::NULL_asn1:
                        // For table or unsupported types
                        std::cout << "Null/Table type" << std::endl;
                        break;
                    default:
                        std::cout << "Unsupported data type" << std::endl;
                        break;
                }
            }
        } else {
            // OID not found
            std::cout << "OID not found in management_db" << std::endl;
            responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
            responseVarBind.length = 0;
            response->error_status = noSuchName;
            response->error_index = i + 1;
        }

        response->variable_binding_list.push_back(responseVarBind);
    }
}
void processGetNextRequest(SNMP_message* request, SNMP_message* response, TypeMyTree& management_db) {
    response->pdu_type = SNMP_message::PduType::GET_RESPONSE;
    response->request_id = request->request_id;
    response->error_status = noError;
    response->error_index = 0;
    response->variable_binding_list.clear();

    // Process each variable binding in the request
    for (size_t i = 0; i < request->variable_binding_list.size(); i++) {
        VariableBind requestVarBind = request->variable_binding_list[i];
        VariableBind responseVarBind;

        // Normalize the OID to fix the issue
        std::string normalizedOid = normalizeOid(requestVarBind.oid);

        std::cout << "GETNEXT request for OID: " << requestVarBind.oid << std::endl;
        std::cout << "Normalized OID: " << normalizedOid << std::endl;

        // Find the next OID in lexicographic order
        std::string nextOid = "";
        for (auto const& item : management_db) {
            if (item.first > normalizedOid) {
                nextOid = item.first;
                break;
            }
        }

        if (nextOid.empty()) {
            // No next OID found (end of MIB)
            std::cout << "End of MIB reached" << std::endl;
            responseVarBind.oid = requestVarBind.oid;
            responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
            responseVarBind.length = 0;
            response->error_status = genErr;
            response->error_index = i + 1;
        } else {
            // Next OID found
            std::cout << "Next OID found: " << nextOid << std::endl;
            responseVarBind.oid = nextOid;

            auto it = management_db.find(nextOid);
            responseVarBind.asn1_type = it->second.data_type;
            responseVarBind.length = it->second.length;

            // Handle different data types
            switch (it->second.data_type) {
                case Asn1DataType::INTEGER:
                    responseVarBind.value.integer_value = it->second.value.integer_value;
                    std::cout << "Integer value: " << responseVarBind.value.integer_value << std::endl;
                    break;
                case Asn1DataType::OCTET_STRING:
                case Asn1DataType::IpAddress:
                    if (it->second.value.char_array_value != nullptr) {
                        responseVarBind.value.char_array_value = it->second.value.char_array_value;
                        std::cout << "String/IP value: " << responseVarBind.value.char_array_value << std::endl;
                    } else {
                        responseVarBind.value.char_array_value = nullptr;
                        std::cout << "String/IP value is null" << std::endl;
                    }
                    break;
                case Asn1DataType::NULL_asn1:
                    // For table or unsupported types
                    std::cout << "Null/Table type" << std::endl;
                    break;
                default:
                    std::cout << "Unsupported data type" << std::endl;
                    break;
            }
        }

        response->variable_binding_list.push_back(responseVarBind);
    }
}

void processSetRequest(SNMP_message* request, SNMP_message* response, TypeMyTree& management_db) {
    // Debug output for start of SET request
    std::cout << "=== START SET REQUEST ===" << std::endl;
    std::cout << "Total Variable Bindings: " << request->variable_binding_list.size() << std::endl;

    // Initialize response
    response->pdu_type = SNMP_message::PduType::GET_RESPONSE;
    response->request_id = request->request_id;
    response->error_status = noError;
    response->error_index = 0;
    response->variable_binding_list.clear();

    // Process each variable binding in the request
    for (size_t i = 0; i < request->variable_binding_list.size(); i++) {
        VariableBind requestVarBind = request->variable_binding_list[i];

        // Debug output for current variable binding
        std::cout << "--- Variable Binding " << i+1 << " ---" << std::endl;
        std::cout << "Original OID: " << requestVarBind.oid << std::endl;

        // Normalize OID
        std::string normalizedOid = normalizeOid(requestVarBind.oid);
        std::cout << "Normalized OID: " << normalizedOid << std::endl;

        // Detailed request information
        std::cout << "Request Details:" << std::endl;
        std::cout << "  ASN1 Type: " << static_cast<int>(requestVarBind.asn1_type) << std::endl;
        std::cout << "  Length: " << requestVarBind.length << std::endl;

        // Prepare response variable binding
        VariableBind responseVarBind;
        responseVarBind.oid = requestVarBind.oid;

        // Find the OID in management database
        auto it = management_db.find(normalizedOid);

        // Special handling for column OIDs
        bool isColumnOid = false;
        if (it == management_db.end()) {
            // Check if this is a direct column OID reference
            if (normalizedOid == OID_DAY_OF_YEAR ||
                normalizedOid == OID_DAILY_ENTERED ||
                normalizedOid == OID_DAILY_LEFT) {

                isColumnOid = true;
                std::cout << "Column OID detected - this requires an instance index" << std::endl;

                // Set error status for column without instance
                response->error_status = noSuchName;
                response->error_index = i + 1;

                // Set null response
                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                response->variable_binding_list.push_back(responseVarBind);
                continue;
            } else {
                std::cout << "ERROR: OID NOT FOUND IN MANAGEMENT DB" << std::endl;

                // Set error status
                response->error_status = noSuchName;
                response->error_index = i + 1;

                // Create a null variable binding for error response
                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                response->variable_binding_list.push_back(responseVarBind);
                continue;
            }
        }

        // Process normally for found OIDs
        // Check access rights
        std::cout << "Access Rights: "
                  << (it->second.max_access == MaxAccess::read_write ? "Read-Write" : "Read-Only")
                  << std::endl;

        // Detailed type checking
        std::cout << "Stored Object Type: " << static_cast<int>(it->second.data_type) << std::endl;
        std::cout << "Received ASN1 Type: " << static_cast<int>(requestVarBind.asn1_type) << std::endl;

        // Check if object is read-only
        if (it->second.max_access != MaxAccess::read_write) {
            std::cout << "ERROR: OBJECT IS READ-ONLY" << std::endl;
            response->error_status = readOnly;
            response->error_index = i + 1;
            responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
        }
        // Check if data type matches
        else if (it->second.data_type != requestVarBind.asn1_type) {
            std::cout << "ERROR: TYPE MISMATCH" << std::endl;
            response->error_status = badValue;
            response->error_index = i + 1;
            responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
        }
        else {
            // Check if this is a table entry
            bool isTableEntry = false;
            std::string columnBase = "";
            int rowIndex = -1;

            // Extract column base and row index if applicable
            if (normalizedOid.find(OID_DAY_OF_YEAR) == 0 && normalizedOid.length() > strlen(OID_DAY_OF_YEAR)) {
                isTableEntry = true;
                columnBase = OID_DAY_OF_YEAR;
                std::string indexPart = normalizedOid.substr(strlen(OID_DAY_OF_YEAR) + 1);
                try {
                    rowIndex = std::stoi(indexPart) - 1; // Convert to 0-based
                } catch (...) {
                    std::cout << "ERROR: Invalid index in OID" << std::endl;
                    response->error_status = badValue;
                    response->error_index = i + 1;
                    responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                    response->variable_binding_list.push_back(responseVarBind);
                    continue;
                }
            }
            else if (normalizedOid.find(OID_DAILY_ENTERED) == 0 && normalizedOid.length() > strlen(OID_DAILY_ENTERED)) {
                isTableEntry = true;
                columnBase = OID_DAILY_ENTERED;
                std::string indexPart = normalizedOid.substr(strlen(OID_DAILY_ENTERED) + 1);
                try {
                    rowIndex = std::stoi(indexPart) - 1; // Convert to 0-based
                } catch (...) {
                    std::cout << "ERROR: Invalid index in OID" << std::endl;
                    response->error_status = badValue;
                    response->error_index = i + 1;
                    responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                    response->variable_binding_list.push_back(responseVarBind);
                    continue;
                }
            }
            else if (normalizedOid.find(OID_DAILY_LEFT) == 0 && normalizedOid.length() > strlen(OID_DAILY_LEFT)) {
                isTableEntry = true;
                columnBase = OID_DAILY_LEFT;
                std::string indexPart = normalizedOid.substr(strlen(OID_DAILY_LEFT) + 1);
                try {
                    rowIndex = std::stoi(indexPart) - 1; // Convert to 0-based
                } catch (...) {
                    std::cout << "ERROR: Invalid index in OID" << std::endl;
                    response->error_status = badValue;
                    response->error_index = i + 1;
                    responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                    response->variable_binding_list.push_back(responseVarBind);
                    continue;
                }
            }

            // Actual SET operation with specific handling
            switch (it->second.data_type) {
                case Asn1DataType::INTEGER:
                    std::cout << "Setting INTEGER value: "
                              << requestVarBind.value.integer_value << std::endl;

                    // For table entries
                    if (isTableEntry) {
                        // Validate index range
                        if (rowIndex < 0 || rowIndex >= g_historyTable.size()) {
                            std::cout << "ERROR: Index out of range" << std::endl;
                            response->error_status = badValue;
                            response->error_index = i + 1;
                            responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                            break;
                        }

                        // Process based on column type
                        if (columnBase == OID_DAY_OF_YEAR) {
                            // Validate day of year (1-366)
                            if (requestVarBind.value.integer_value < 1 ||
                                requestVarBind.value.integer_value > 366) {
                                std::cout << "ERROR: Invalid day of year" << std::endl;
                                response->error_status = badValue;
                                response->error_index = i + 1;
                                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                                break;
                            }
                            g_historyTable[rowIndex].dayOfYear = requestVarBind.value.integer_value;
                        }
                        else if (columnBase == OID_DAILY_ENTERED) {
                            // Validate daily entered value (non-negative)
                            if (requestVarBind.value.integer_value < 0) {
                                std::cout << "ERROR: Daily entered value cannot be negative" << std::endl;
                                response->error_status = badValue;
                                response->error_index = i + 1;
                                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                                break;
                            }
                            g_historyTable[rowIndex].peopleEntered = requestVarBind.value.integer_value;
                        }
                        else if (columnBase == OID_DAILY_LEFT) {
                            // Validate daily left value (non-negative)
                            if (requestVarBind.value.integer_value < 0) {
                                std::cout << "ERROR: Daily left value cannot be negative" << std::endl;
                                response->error_status = badValue;
                                response->error_index = i + 1;
                                responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
                                break;
                            }
                            g_historyTable[rowIndex].peopleLeft = requestVarBind.value.integer_value;
                        }
                    }
                    // Regular integer field
                    else {
                        it->second.value.integer_value = requestVarBind.value.integer_value;
                    }

                    // Set the response if no errors occurred
                    if (response->error_status == noError) {
                        responseVarBind = requestVarBind;
                    }
                    break;

                case Asn1DataType::OCTET_STRING:
                case Asn1DataType::IpAddress:
                    std::cout << "Setting STRING/IP value: "
                              << (requestVarBind.value.char_array_value ?
                                   requestVarBind.value.char_array_value : "NULL") << std::endl;

                    it->second.value.char_array_value = requestVarBind.value.char_array_value;
                    it->second.length = requestVarBind.length;
                    responseVarBind = requestVarBind;
                    break;

                default:
                    std::cout << "UNSUPPORTED DATA TYPE" << std::endl;
                    response->error_status = badValue;
                    response->error_index = i + 1;
                    responseVarBind.asn1_type = Asn1DataType::NULL_asn1;
            }
        }

        // Add the variable binding to the response
        response->variable_binding_list.push_back(responseVarBind);
    }

    // Debug output for end of SET request
    std::cout << "=== END SET REQUEST ===" << std::endl;
}

int main(int argc, char* argv[]) {
    SOCKET sd;
    int myerror;
    myerror = startSocket(sd, PORT);
    if (myerror < 0) {
        std::cerr << "Failed to start socket" << std::endl;
        return -1;
    }

    ssize_t received_msg_length;
    char recv_msg_buffer[SNMP_MSG_MAX_LEN];
    struct sockaddr_in client_ip_info;

    // Initialize the management database
    TypeMyTree management_db;
    initializeManagementDB(management_db);

    std::cout << "SNMP Agent started. Listening on port " << PORT << "..." << std::endl;

    // Main loop - keep listening for SNMP requests
    while (1) {
        myerror = receiveFromSocket(sd, recv_msg_buffer, received_msg_length, client_ip_info);

        std::cout << "Received packet from " << inet_ntoa(client_ip_info.sin_addr) << ":" << ntohs(client_ip_info.sin_port) << std::endl;
        std::cout << "Number of bytes = " << received_msg_length << std::endl;
        std::cout << "Data in hexa:" << std::endl;
        printAsHexa(recv_msg_buffer, received_msg_length);

        char snmp_response_buffer[SNMP_MSG_MAX_LEN];
        ssize_t response_msg_length = 0;

        // Parse the received SNMP message
        SNMP_message *request_msg = new SNMP_message(recv_msg_buffer);

        // Prepare response message
        SNMP_message *response_msg = new SNMP_message();
        response_msg->version = request_msg->version;
        response_msg->comunity = request_msg->comunity;

        // Process the request based on PDU type
        switch (request_msg->pdu_type) {
            case SNMP_message::PduType::GET_REQUEST:
                std::cout << "Received GET request" << std::endl;
                processGetRequest(request_msg, response_msg, management_db);
                break;

            case SNMP_message::PduType::GET_NEXT_REQUEST:
                std::cout << "Received GET-NEXT request" << std::endl;
                processGetNextRequest(request_msg, response_msg, management_db);
                break;

            case SNMP_message::PduType::SET_REQUEST:
                std::cout << "Received SET request" << std::endl;
                processSetRequest(request_msg, response_msg, management_db);
                break;

            default:
                std::cout << "Unknown Request Type: " << std::hex << (request_msg->pdu_type & 0xFF) << std::dec << std::endl;
                response_msg->pdu_type = SNMP_message::PduType::GET_RESPONSE;
                response_msg->request_id = request_msg->request_id;
                response_msg->error_status = genErr;
                response_msg->error_index = 0;
                response_msg->variable_binding_list = request_msg->variable_binding_list;
                break;
        }

        // Encode the response message
        std::cout << "Encoding response message..." << std::endl;
        response_msg_length = response_msg->to_tlv(snmp_response_buffer, SNMP_MSG_MAX_LEN);
        std::cout << "to_tlv result: " << response_msg_length << std::endl;

        if (response_msg_length > 0) {
            std::cout << "Generated response:" << std::endl;
            std::cout << "Number of bytes = " << response_msg_length << std::endl;
            std::cout << "Data in hexa:" << std::endl;
            printAsHexa(snmp_response_buffer, response_msg_length);

            myerror = sendToSocket(sd, snmp_response_buffer, response_msg_length, client_ip_info);
        } else {
            std::cout << "Failed to generate response. Error code: " << response_msg_length << std::endl;

            // For debugging, print the response message details
            std::cout << "Response message details:" << std::endl;
            std::cout << "PDU type: " << static_cast<int>(response_msg->pdu_type) << std::endl;
            std::cout << "Request ID: " << response_msg->request_id << std::endl;
            std::cout << "Error status: " << response_msg->error_status << std::endl;
            std::cout << "Error index: " << response_msg->error_index << std::endl;
            std::cout << "Number of variable bindings: " << response_msg->variable_binding_list.size() << std::endl;

            for (size_t i = 0; i < response_msg->variable_binding_list.size(); i++) {
                std::cout << "  VarBind " << i + 1 << ":" << std::endl;
                std::cout << "    OID: " << response_msg->variable_binding_list[i].oid << std::endl;
                std::cout << "    Type: " << static_cast<int>(response_msg->variable_binding_list[i].asn1_type) << std::endl;
                std::cout << "    Length: " << response_msg->variable_binding_list[i].length << std::endl;
            }
        }

        // Clean up
        delete request_msg;
        delete response_msg;
    }

    return 0;
}

/*
0x30 0x28 - SEQUENCE (0x30) with length 40 bytes (0x28)
    This is the start of the SNMP message

    0x02 0x01 0x00 - INTEGER (0x02) with length 1 byte (0x01) and value 0 (0x00)
        This represents the SNMP version (0 = SNMPv1)

    0x04 0x06 0x70 0x75 0x62 0x6C 0x69 0x63 - OCTET STRING (0x04) with length 6 bytes (0x06)
        Value: 0x70 0x75 0x62 0x6C 0x69 0x63 = "public" (community string)

    0xA2 0x1B - PDU Type GET_RESPONSE (0xA2) with length 27 bytes (0x1B)

        0x02 0x01 0x03 - INTEGER (0x02) with length 1 byte (0x01) and value 3 (0x03)
            This is the request ID

        0x02 0x01 0x00 - INTEGER (0x02) with length 1 byte (0x01) and value 0 (0x00)
            This is the error status (0 = noError)

        0x02 0x01 0x00 - INTEGER (0x02) with length 1 byte (0x01) and value 0 (0x00)
            This is the error index

        0x30 0x10 - SEQUENCE (0x30) with length 16 bytes (0x10)
            This begins the variable binding list

            0x30 0x0E - SEQUENCE (0x30) with length 14 bytes (0x0E)
                This is a single variable binding

                0x06 0x09 0x2B 0x06 0x01 0x02 0x01 0x32 0x01 0x01 0x00 - OBJECT IDENTIFIER (0x06) with length 9 bytes (0x09)
                    This is the OID: 1.3.6.1.2.1.50.1.1.0
                    (0x2B is 43 decimal, which encodes first two nodes as 1.3)

                0x02 0x01 0x00 - INTEGER (0x02) with length 1 byte (0x01) and value 0 (0x00)
                    This is the value of the OID
 */



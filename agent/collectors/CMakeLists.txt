add_library(reaperwatch_collectors
    process_monitor.cpp
    event_json.cpp
    etw_consumer.cpp
    file_monitor.cpp
    network_monitor.cpp
    registry_monitor.cpp
)

# ${CMAKE_SOURCE_DIR}/third_party holds vendored header-only deps (nlohmann/json).
target_include_directories(reaperwatch_collectors PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/third_party
)

# ntdll    -> NtQueryInformationProcess (declared in <winternl.h>)
# advapi32 -> token/SID APIs: OpenProcessToken, LookupAccountSid, ConvertSidToStringSid
# bcrypt   -> CNG hashing: BCryptOpenAlgorithmProvider, BCryptHashData, ...
# wintrust -> Authenticode verification: WinVerifyTrust
# crypt32  -> certificate/signer extraction: CryptQueryObject, CertGetNameString
# tdh      -> ETW event payload decoding: TdhGetProperty
# reaperwatch_transport -> durable event sink (data/events.jsonl)
# PUBLIC so the dependencies propagate to the final agent executable at link time.
target_link_libraries(reaperwatch_collectors PUBLIC ntdll advapi32 bcrypt wintrust crypt32 tdh reaperwatch_transport)


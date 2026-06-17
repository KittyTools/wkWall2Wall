#include "WaTaskMessageCodec.h"

#include <vector>

namespace {

void writeU16(std::uint8_t* output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value & 0xFF);
    output[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

std::uint16_t readU16(const std::uint8_t* input) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(input[0])
        | (static_cast<std::uint16_t>(input[1]) << 8));
}

bool validatePayloadSize(std::size_t payloadSize, std::string& error) {
    if (payloadSize == 0) {
        error = "WA task message payload is empty";
        return false;
    }

    if (payloadSize > kWallGameMessageMaxPayloadBytes) {
        error = "WA task message payload is too large";
        return false;
    }

    return true;
}

} // namespace

bool packWallGameMessageForTaskMessageData(
    const WallGameMessage& message,
    WaWallTaskMessageData& data,
    std::size_t& dataSize,
    std::string& error) {
    data = WaWallTaskMessageData{};
    dataSize = 0;
    error.clear();

    if (!isWallGameTaskMessage(message.taskMessageType)) {
        error = "not a wkWall2Wall task message";
        return false;
    }

    if (!validatePayloadSize(message.payload.size(), error)) {
        return false;
    }

    data.payloadSize = static_cast<std::uint16_t>(message.payload.size());
    for (std::size_t index = 0; index < message.payload.size(); ++index) {
        data.payload[index] = message.payload[index];
    }

    dataSize = kWaWallTaskMessageRuntimeHeaderBytes + message.payload.size();
    return true;
}

bool unpackWallGameMessageFromTaskMessageData(
    const void* data,
    std::size_t dataSize,
    WallGameMessage& message,
    std::string& error) {
    message = WallGameMessage{};
    error.clear();

    if (data == nullptr) {
        error = "WA task message data is null";
        return false;
    }

    if (dataSize < kWaWallTaskMessageRuntimeHeaderBytes) {
        error = "WA task message data is too small";
        return false;
    }

    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(data);
    const std::size_t payloadSize = readU16(bytes);
    if (!validatePayloadSize(payloadSize, error)) {
        return false;
    }

    const std::size_t requiredBytes = kWaWallTaskMessageRuntimeHeaderBytes + payloadSize;
    if (dataSize < requiredBytes) {
        error = "WA task message data payload is truncated";
        return false;
    }

    std::vector<std::uint8_t> payload(
        bytes + kWaWallTaskMessageRuntimeHeaderBytes,
        bytes + kWaWallTaskMessageRuntimeHeaderBytes + payloadSize);
    return makeWallGameMessage(payload, message, error);
}

bool serializeWallTaskMessageForWa(
    const WallGameMessage& message,
    std::uint8_t* output,
    std::size_t outputCapacity,
    std::size_t& bytesWritten,
    std::string& error) {
    bytesWritten = 0;
    error.clear();

    if (output == nullptr) {
        error = "WA task message output buffer is null";
        return false;
    }

    if (!isWallGameTaskMessage(message.taskMessageType)) {
        error = "not a wkWall2Wall task message";
        return false;
    }

    if (!validatePayloadSize(message.payload.size(), error)) {
        return false;
    }

    const std::size_t requiredBytes =
        kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes + message.payload.size();
    if (outputCapacity < requiredBytes) {
        error = "WA task message output buffer is too small";
        return false;
    }

    output[0] = message.taskMessageType;
    writeU16(output + kWaTaskMessageTypeBytes, static_cast<std::uint16_t>(message.payload.size()));
    for (std::size_t index = 0; index < message.payload.size(); ++index) {
        output[index + kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes] = message.payload[index];
    }

    bytesWritten = requiredBytes;
    return true;
}

bool deserializeWallTaskMessageFromWa(
    const std::uint8_t* input,
    std::size_t inputSize,
    WallGameMessage& message,
    std::size_t& bytesRead,
    std::string& error) {
    message = WallGameMessage{};
    bytesRead = 0;
    error.clear();

    if (input == nullptr) {
        error = "WA task message input buffer is null";
        return false;
    }

    if (inputSize < kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes) {
        error = "WA task message input buffer is too small";
        return false;
    }

    const std::uint8_t taskMessageType = input[0];
    if (!isWallGameTaskMessage(taskMessageType)) {
        error = "not a wkWall2Wall task message";
        return false;
    }

    const std::size_t payloadSize = readU16(input + kWaTaskMessageTypeBytes);
    if (!validatePayloadSize(payloadSize, error)) {
        return false;
    }

    const std::size_t requiredBytes =
        kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes + payloadSize;
    if (inputSize < requiredBytes) {
        error = "WA task message payload is truncated";
        return false;
    }

    std::vector<std::uint8_t> payload(
        input + kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes,
        input + requiredBytes);
    if (!makeWallGameMessage(payload, message, error)) {
        return false;
    }

    bytesRead = requiredBytes;
    return true;
}

bool serializeWallTaskMessageDataForWa(
    std::uint32_t taskMessageType,
    const void* taskMessageData,
    std::size_t taskMessageDataSize,
    std::uint8_t* output,
    std::size_t outputCapacity,
    std::size_t& bytesWritten,
    std::string& error) {
    bytesWritten = 0;
    error.clear();

    if (!isWallGameTaskMessage(taskMessageType)) {
        error = "not a wkWall2Wall task message";
        return false;
    }

    WallGameMessage message;
    if (!unpackWallGameMessageFromTaskMessageData(taskMessageData, taskMessageDataSize, message, error)) {
        return false;
    }

    return serializeWallTaskMessageForWa(message, output, outputCapacity, bytesWritten, error);
}

bool deserializeWallTaskMessageDataFromWa(
    const std::uint8_t* input,
    std::size_t inputSize,
    void* outputTaskMessageData,
    std::size_t outputCapacity,
    std::uint32_t& taskMessageType,
    std::size_t& taskMessageDataSize,
    std::size_t& bytesRead,
    std::string& error) {
    taskMessageType = 0;
    taskMessageDataSize = 0;
    bytesRead = 0;
    error.clear();

    WallGameMessage message;
    if (!deserializeWallTaskMessageFromWa(input, inputSize, message, bytesRead, error)) {
        return false;
    }

    WaWallTaskMessageData runtimeData;
    std::size_t runtimeDataSize = 0;
    if (!packWallGameMessageForTaskMessageData(message, runtimeData, runtimeDataSize, error)) {
        bytesRead = 0;
        return false;
    }

    if (outputTaskMessageData == nullptr) {
        taskMessageType = message.taskMessageType;
        taskMessageDataSize = runtimeDataSize;
        bytesRead = 0;
        error = "WA task message output data buffer is null";
        return false;
    }

    if (outputCapacity < runtimeDataSize) {
        taskMessageType = message.taskMessageType;
        taskMessageDataSize = runtimeDataSize;
        bytesRead = 0;
        error = "WA task message output data buffer is too small";
        return false;
    }

    std::uint8_t* output = static_cast<std::uint8_t*>(outputTaskMessageData);
    const std::uint8_t* inputData = reinterpret_cast<const std::uint8_t*>(&runtimeData);
    for (std::size_t index = 0; index < runtimeDataSize; ++index) {
        output[index] = inputData[index];
    }

    taskMessageType = message.taskMessageType;
    taskMessageDataSize = runtimeDataSize;
    return true;
}

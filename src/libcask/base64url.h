class Base64Url {
public:
    static int DecodeFromChars(const char* source, std::span<uint8_t> destination) {
        // Base64 URL-safe characters
        static const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_";

        // Replace URL-safe characters with standard Base64 characters
        std::string base64_input(source.begin(), source.end());
        std::replace(base64_input.begin(), base64_input.end(), '-', '+');
        std::replace(base64_input.begin(), base64_input.end(), '_', '/');

        // Pad with '=' to make the length a multiple of 4
        while (base64_input.size() % 4 != 0) {
            base64_input += '=';
        }

        // Decode the Base64 string
        return DecodeBase64(base64_input, destination);
    }

private:
    static int DecodeBase64(const std::string& input, std::span<uint8_t> destination) {
        static const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        size_t in_len = input.size();
        if (in_len % 4 != 0) {
            throw std::invalid_argument("Invalid Base64 input length.");
        }

        size_t out_len = in_len / 4 * 3;
        if (input[in_len - 1] == '=') out_len--;
        if (input[in_len - 2] == '=') out_len--;

        if (destination.size() < out_len) {
            throw std::invalid_argument("Destination span is too small to hold the decoded data.");
        }

        size_t i = 0, j = 0;
        uint32_t buffer = 0;
        int bits_collected = 0;

        for (char c : input) {
            if (c == '=') break;
            auto pos = base64_chars.find(c);
            if (pos == std::string::npos) {
                throw std::invalid_argument("Invalid Base64 character.");
            }

            buffer = (buffer << 6) | pos;
            bits_collected += 6;
            if (bits_collected >= 8) {
                bits_collected -= 8;
                destination[j++] = (buffer >> bits_collected) & 0xFF;
            }
        }

        return static_cast<int>(j);
    }
};

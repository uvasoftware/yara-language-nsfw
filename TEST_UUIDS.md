# Test UUIDs for Language Detection

Each language YARA rule file includes a test rule that matches a unique UUID. These UUIDs can be used to verify that language-specific detection is working correctly.

## Usage

To test a specific language, include its UUID in your test content. The corresponding language rule will match.

Example:
```bash
echo "Test content: E78F3BC5-9633-4FF8-9311-148ACC4880DF" > test.txt
yara src/en-language-nsfw.yara test.txt
# Output: content_en_language_nsfw_test test.txt
```

## Test UUIDs by Language

| Language Code | Language Name | Test UUID |
|---------------|--------------|-----------|
| `ar` | Arabic | `DC50B92E-2C51-4083-A848-D13897C837A9` |
| `bn` | Bengali | `7F8E3A12-9D4B-4F2C-B8E1-5A6C9D2E4F7B` |
| `cs` | Czech | `2A5B8C3D-4E6F-4A1B-9C2D-3E4F5A6B7C8D` |
| `da` | Danish | `9E3F4A5B-6C7D-4E8F-A9B1-2C3D4E5F6A7B` |
| `de` | German | `38555D30-84DD-4A1E-808C-E1B1F6C9915E` |
| `en` | English | `E78F3BC5-9633-4FF8-9311-148ACC4880DF` |
| `en-racial` | English (Racial Slurs) | `1B2C3D4E-5F6A-4B7C-8D9E-0F1A2B3C4D5E` |
| `eo` | Esperanto | `6F7A8B9C-0D1E-4F2A-3B4C-5D6E7F8A9B0C` |
| `es` | Spanish | `4D5E6F7A-8B9C-40D1-E2F3-A4B5C6D7E8F9` |
| `fi` | Finnish | `A1B2C3D4-E5F6-47A8-B9C0-D1E2F3A4B5C6` |
| `fr` | French | `06554638-D821-457B-B5D2-AB40B8A14874` |
| `hi` | Hindi | `8C9D0E1F-2A3B-44C5-D6E7-F8A9B0C1D2E3` |
| `hu` | Hungarian | `3E4F5A6B-7C8D-49E0-F1A2-B3C4D5E6F7A8` |
| `it` | Italian | `9A0B1C2D-3E4F-45A6-B7C8-D9E0F1A2B3C4` |
| `ja` | Japanese | `5B6C7D8E-9F0A-41B2-C3D4-E5F6A7B8C9D0` |
| `ko` | Korean | `0C1D2E3F-4A5B-46C7-D8E9-F0A1B2C3D4E5` |
| `nl` | Dutch | `7D8E9F0A-1B2C-43D4-E5F6-A7B8C9D0E1F2` |
| `no` | Norwegian | `2E3F4A5B-6C7D-48E9-F0A1-B2C3D4E5F6A7` |
| `pl` | Polish | `A8B9C0D1-E2F3-44A5-B6C7-D8E9F0A1B2C3` |
| `pt` | Portuguese | `4F5A6B7C-8D9E-40F1-A2B3-C4D5E6F7A8B9` |
| `ru` | Russian | `1A2B3C4D-5E6F-47A8-B9C0-D1E2F3A4B5C6` |
| `sv` | Swedish | `6B7C8D9E-0F1A-42B3-C4D5-E6F7A8B9C0D1` |
| `th` | Thai | `2C3D4E5F-6A7B-48C9-D0E1-F2A3B4C5D6E7` |
| `tr` | Turkish | `8D9E0F1A-2B3C-44D5-E6F7-A8B9C0D1E2F3` |
| `zh` | Chinese | `4E5F6A7B-8C9D-40E1-F2A3-B4C5D6E7F8A9` |


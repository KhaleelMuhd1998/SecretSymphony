package secretsymphony

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	SecretSymphonyVersion  = "0.0.1"
	SecretSymphonyPlatform = "Go"
	EpochOffset            = 946684800 // Jan 1, 2000 UTC
)

// Returns current custom time (seconds since Jan 1, 2000)
func GetCurrentCustomTime() int64 {
	return time.Now().Unix() - EpochOffset
}

// Converts a timestamp in milliseconds to custom time
func ConvertToCustomTime(timestamp int64) int64 {
	return (timestamp / 1000) - EpochOffset
}

// Converts custom time to a JavaScript-style timestamp (ms)
func ConvertFromCustomTime(customTime int64) int64 {
	return (customTime + EpochOffset) * 1000
}

// Generates a random key of a given length
func GenerateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	return key, err
}

// XOR two byte slices
func XORBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Shift key characters using PIN and expiry-based shift values
func ShiftKeyCharacters(key []byte, shifts []int) []byte {
	shifted := make([]byte, len(key))
	inc := true
	for i := range key {
		shift := shifts[i%len(shifts)]
		if inc {
			shifted[i] = byte((int(key[i]) + shift) % 256)
		} else {
			shifted[i] = byte((int(key[i]) - shift + 256) % 256)
		}
		inc = !inc
	}
	return shifted
}

// Reverse the shifted key to retrieve original key
func ReverseShiftKeyCharacters(key []byte, shifts []int) []byte {
	original := make([]byte, len(key))
	inc := true
	for i := range key {
		shift := shifts[i%len(shifts)]
		if inc {
			original[i] = byte((int(key[i]) - shift + 256) % 256)
		} else {
			original[i] = byte((int(key[i]) + shift) % 256)
		}
		inc = !inc
	}
	return original
}

// Converts PIN string to a slice of int shift values
func GetUserShiftValues(pin string) ([]int, error) {
	shifts := make([]int, len(pin))
	for i, c := range pin {
		d := int(c - '0')
		if d < 0 || d > 9 {
			return nil, errors.New("PIN must contain only digits")
		}
		shifts[i] = d
	}
	return shifts, nil
}

// Generate SHA-256 hash of data and return as hex string
func GenerateSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// DecryptFileSS handles decryption of a file using PIN and metadata
func DecryptFileSS(metaFile, encFile, keyFile, pin, outputDir string, deleteAfter bool) (map[string]interface{}, error) {
	if len(pin) < 4 || len(pin) > 8 {
		return nil, errors.New("PIN must be 4 to 8 digits")
	}
	shiftValues, err := GetUserShiftValues(pin)
	if err != nil {
		return nil, err
	}
	metaBytes, err := ioutil.ReadFile(metaFile)
	if err != nil {
		return nil, err
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(metaBytes, &metadata); err != nil {
		return nil, err
	}
	expectedHash := metadata["default"].(map[string]interface{})["hash"].(string)
	format := metadata["default"].(map[string]interface{})["format"].(string)

	encBytes, err := ioutil.ReadFile(encFile)
	if err != nil {
		return nil, err
	}

	flag := encBytes[0]
	fullShift := append([]int{}, shiftValues...)
	var encrypted []byte

	if flag == 1 {
		masked := encBytes[1:9]
		pinHash := sha256.Sum256([]byte(pin))
		mask := pinHash[:8]
		maskedInt := new(big.Int).SetBytes(masked)
		maskInt := new(big.Int).SetBytes(mask)
		expiry := maskedInt.Xor(maskedInt, maskInt).Int64()
		if GetCurrentCustomTime() > expiry {
			return nil, errors.New("File has expired")
		}
		expiryDigits := strings.Split(strconv.FormatInt(expiry, 10), "")
		for _, d := range expiryDigits {
			val, _ := strconv.Atoi(d)
			fullShift = append(fullShift, val)
		}
		encrypted = encBytes[9:]
	} else {
		encrypted = encBytes[1:]
	}

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	originalKey := ReverseShiftKeyCharacters(keyBytes, fullShift)
	decryptedB64 := XORBytes(encrypted, originalKey)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(decryptedB64)))
	n, err := base64.StdEncoding.Decode(decoded, decryptedB64)
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n]
	actualHash := GenerateSHA256(decoded)
	if actualHash != expectedHash {
		return nil, errors.New("Decryption failed: hash mismatch")
	}

	if outputDir == "" {
		outputDir = filepath.Dir(encFile)
	}
	baseName := strings.TrimSuffix(filepath.Base(encFile), ".sse1")
	outputPath := filepath.Join(outputDir, baseName+"_ss."+format)
	if err := ioutil.WriteFile(outputPath, decoded, 0644); err != nil {
		return nil, err
	}

	if deleteAfter {
		_ = os.Remove(metaFile)
		_ = os.Remove(encFile)
		_ = os.Remove(keyFile)
	}

	return map[string]interface{}{
		"status":              true,
		"decrypted_file_path": outputPath,
		"custom":              metadata["custom"],
	}, nil
}

// EncryptFileSS handles file encryption and metadata generation
func EncryptFileSS(inputPath, pin, outputDir string, expiryTime *int64, customData map[string]string) (map[string]string, error) {
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return nil, errors.New("input file not found")
	}
	if len(pin) < 4 || len(pin) > 8 {
		return nil, errors.New("PIN must be 4 to 8 digits")
	}
	shiftValues, err := GetUserShiftValues(pin)
	if err != nil {
		return nil, err
	}

	inputBytes, err := ioutil.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(inputBytes)))
	base64.StdEncoding.Encode(base64Data, inputBytes)

	hash := GenerateSHA256(inputBytes)
	key, err := GenerateRandomKey(len(base64Data))
	if err != nil {
		return nil, err
	}

	fullShift := append([]int{}, shiftValues...)
	var expiryBuffer []byte
	if expiryTime != nil {
		expiry := ConvertToCustomTime(*expiryTime)
		expiryDigits := strings.Split(strconv.FormatInt(expiry, 10), "")
		for _, d := range expiryDigits {
			val, _ := strconv.Atoi(d)
			fullShift = append(fullShift, val)
		}
		pinHash := sha256.Sum256([]byte(pin))
		mask := pinHash[:8]
		maskInt := new(big.Int).SetBytes(mask)
		masked := big.NewInt(expiry).Xor(big.NewInt(expiry), maskInt).Bytes()
		paddedMasked := append([]byte{1}, make([]byte, 8-len(masked))...)
		expiryBuffer = append(paddedMasked, masked...)
	} else {
		expiryBuffer = []byte{0}
	}

	scrambledKey := ShiftKeyCharacters(key, fullShift)
	encrypted := XORBytes(base64Data, key)
	finalEncrypted := append(expiryBuffer, encrypted...)

	if outputDir == "" {
		outputDir = filepath.Dir(inputPath)
	}
	base := filepath.Base(inputPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	metaFile := filepath.Join(outputDir, name+".sse0")
	encFile := filepath.Join(outputDir, name+".sse1")
	keyFile := filepath.Join(outputDir, name+".sse2")

	metadata := map[string]interface{}{
		"secretsymphony": map[string]string{
			"version":  SecretSymphonyVersion,
			"platform": SecretSymphonyPlatform,
		},
		"default": map[string]string{
			"hash":   hash,
			"format": strings.TrimPrefix(filepath.Ext(inputPath), "."),
		},
		"custom": customData,
	}
	metaJSON, _ := json.MarshalIndent(metadata, "", "  ")
	_ = ioutil.WriteFile(metaFile, metaJSON, 0644)
	_ = ioutil.WriteFile(encFile, finalEncrypted, 0644)
	_ = ioutil.WriteFile(keyFile, scrambledKey, 0644)

	return map[string]string{
		"metadata_file_path":  metaFile,
		"encrypted_file_path": encFile,
		"key_file_path":       keyFile,
	}, nil
}

/*
* AJ Savino
*/
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Linq;
using System.Diagnostics;

//Symmetric Encryption
public class AESPlus {
	protected const int KEY_SIZE = 256; //(128, 192, 256)
	protected const int BLOCK_SIZE = 128;
	protected const int CHUNK_SIZE = 4096; //4kb

	public delegate void OnProgressHandler(object sender, AESPlusProgressEventArgs evt);
	public static event OnProgressHandler OnProgress;

	public static CancellationToken? CancelToken = null;

	public static CipherMode MODE = CipherMode.CBC;
	public static PaddingMode PADDING = PaddingMode.PKCS7;
	public static Boolean UsePlusCrypt = false;

	public static void EncryptFile(string fileName, string password){
		EncryptFile(fileName, ComputeKey(password), ComputeIV(password));
	}
	public static void EncryptFile(string fileName, byte[] key, byte[] iv){
		string fileNameEncrypted = fileName + ".encrypted";
		try {
			using (FileStream inputFS = new FileStream(fileName, FileMode.Open, FileAccess.Read)){
				using (FileStream outputFS = new FileStream(fileNameEncrypted, FileMode.Create, FileAccess.Write)){
					EncryptStream(inputFS, outputFS, key, iv);
				}
			}
			ReplaceFile(fileName, fileNameEncrypted);
		} finally {
			File.Delete(fileNameEncrypted);
		}
	}

	public static void DecryptFile(string fileName, string password){
		DecryptFile(fileName, ComputeKey(password), ComputeIV(password));
	}
	public static void DecryptFile(string fileName, byte[] key, byte[] iv){
		string fileNameDecrypted = fileName + ".decrypted";
		try {
			using (FileStream inputFS = new FileStream(fileName, FileMode.Open, FileAccess.Read)){
				using (FileStream outputFS = new FileStream(fileNameDecrypted, FileMode.Create, FileAccess.Write)){
					DecryptStream(inputFS, outputFS, key, iv);
				}
			}
			ReplaceFile(fileName, fileNameDecrypted);
		} finally {
			File.Delete(fileNameDecrypted);
		}
	}

	public static string EncryptString(string input, string password){
		return EncryptString(input, ComputeKey(password), ComputeIV(password));
	}
	public static string EncryptString(string input, byte[] key, byte[] iv){
		using (MemoryStream inputMS = new MemoryStream()){
			byte[] inputBytes = Encoding.UTF8.GetBytes(input);
			inputMS.Write(inputBytes, 0, inputBytes.Length);
			inputMS.Position = 0;
			using (MemoryStream outputMS = new MemoryStream()){
				EncryptStream(inputMS, outputMS, key, iv);
				return Convert.ToBase64String(outputMS.ToArray());
			}
		}
	}

	public static string DecryptString(string input, string password){
		return DecryptString(input, ComputeKey(password), ComputeIV(password));
	}
	public static string DecryptString(string input, byte[] key, byte[] iv){
		using (MemoryStream inputMS = new MemoryStream()){
			byte[] inputBytes = Convert.FromBase64String(input);
			inputMS.Write(inputBytes, 0, inputBytes.Length);
			inputMS.Position = 0;
			using (MemoryStream outputMS = new MemoryStream()){
				DecryptStream(inputMS, outputMS, key, iv);
				return Encoding.UTF8.GetString(outputMS.ToArray());
			}
		}
	}

	public static void EncryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv){
		using (RijndaelManaged aes = new RijndaelManaged()){
			CryptoStream cs = null;
			try {
				aes.Mode = MODE;
				aes.Padding = PADDING;
				aes.BlockSize = BLOCK_SIZE;
				aes.KeySize = KEY_SIZE;
				aes.Key = key;
				aes.IV = iv;
				
				cs = new CryptoStream(outputStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
				byte[] buffer = new byte[CHUNK_SIZE];
				int readSize;
				int offset = 0;
				while ((readSize = inputStream.Read(buffer, 0, CHUNK_SIZE)) > 0){
					if (CancelToken != null && CancelToken.Value.IsCancellationRequested){
						CancelToken.Value.ThrowIfCancellationRequested();
					}
					if (UsePlusCrypt){
						//PlusCrypt(buffer, key, salt, (byte)(offset % 0xFF));
					}
					cs.Write(buffer, 0, readSize);
					offset++;
					if (OnProgress != null){
						OnProgress(null, new AESPlusProgressEventArgs((float)inputStream.Position / (float)inputStream.Length));
					}
				}
				cs.FlushFinalBlock();
			} finally {
				aes.Dispose();
			}
		}
	}

	public static void DecryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv){
		using (RijndaelManaged aes = new RijndaelManaged()){
			CryptoStream cs = null;
			try {
				aes.Mode = MODE;
				aes.Padding = PADDING;
				aes.BlockSize = BLOCK_SIZE;
				aes.KeySize = KEY_SIZE;
				aes.Key = key;
				aes.IV = iv;

				cs = new CryptoStream(inputStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read);
				byte[] buffer = new byte[CHUNK_SIZE];
				int readSize;
				int offset = 0;
				while ((readSize = cs.Read(buffer, 0, CHUNK_SIZE)) > 0){
					if (CancelToken != null && CancelToken.Value.IsCancellationRequested){
						CancelToken.Value.ThrowIfCancellationRequested();
					}
					if (UsePlusCrypt){
						//PlusCrypt(buffer, key, salt, (byte)(offset % 0xFF));
					}
					outputStream.Write(buffer, 0, readSize);
					offset++;
					if (OnProgress != null){
						OnProgress(null, new AESPlusProgressEventArgs((float)inputStream.Position / (float)inputStream.Length));
					}
				}
			} finally {
				aes.Dispose();
			}
		}
	}
	
	private static void ReplaceFile(string fileToReplace, string replaceWithFile){
		if (!File.Exists(fileToReplace) || !File.Exists(replaceWithFile)){
			throw new Exception("File replacement failed.");
		}
		using (FileStream inputFS = new FileStream(replaceWithFile, FileMode.Open, FileAccess.Read)){
			using (FileStream outputFS = new FileStream(fileToReplace, FileMode.Create, FileAccess.Write)){
				byte[] buffer = new byte[CHUNK_SIZE];
				int readSize;
				while ((readSize = inputFS.Read(buffer, 0, CHUNK_SIZE)) > 0){
					outputFS.Write(buffer, 0, readSize);
				}
			}
		}
	}

	private static byte[] ComputeIV(String password){
		SHA256 sha256 = SHA256.Create();
		byte[] iv = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
		int ivLen = iv.Length;
		byte[] tempIV = new byte[ivLen];
		for (int i = 0; i < ivLen; i++){
			tempIV[i] = (byte)((int)iv[i] ^ (((int)iv[i] + (int)iv[ivLen - i - 1]) % 0xFF));
		}
		iv = sha256.ComputeHash(tempIV);
		tempIV = new byte[ivLen >> 1];
		ivLen = tempIV.Length;
		for (int i = 0; i < ivLen; i++){
			tempIV[i] = (byte)((int)iv[i] ^ (int)iv[i + 1]);
		}
		return tempIV;
	}

	private static byte[] ComputeKey(String password){
		SHA256 sha256 = SHA256.Create();
		byte[] newKey = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
		int keyLen = newKey.Length;
		byte[] tempKey = new byte[keyLen];
		for (int i = 0; i < keyLen; i++){
			tempKey[i] = (byte)((int)newKey[i] ^ (((int)newKey[i] + (int)newKey[keyLen - i - 1]) % 0xFF));
			tempKey[i] = (byte)((int)newKey[i] ^ (((int)tempKey[keyLen - i - 1] + (i + newKey[i] + tempKey[i])) % 0xFF));
		}
		newKey = sha256.ComputeHash(tempKey);
		return newKey;
	}

	//Proprietary encryption
	private static byte[] PlusCrypt(byte[] buffer, byte[] key, byte[] salt, byte offset){
		int bufferLen = buffer.Length;
		int keyLen = key.Length;
		byte[] preHash = new byte[]{offset}.Concat(key).Concat(salt).ToArray();
		byte[] hash = SHA512.Create().ComputeHash(preHash);
		int hashLen = hash.Length;
		int hashIndex = 0;
		for (int i = 0; i < bufferLen; i++){
			byte hashByte = hash[hashIndex];
			buffer[i] = (byte)((int)buffer[i] ^ (((int)hashByte + (int)offset + i) % 0xFF));
			hashIndex++;
			if (hashIndex == hashLen){
				hashIndex = 0;
			}
		}
		return buffer;
	}

	public static byte[] StringToByteArray(string hex) {
		return Enumerable.Range(0, hex.Length)
						 .Where(x => x % 2 == 0)
						 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
						 .ToArray();
	}
}

public class AESPlusProgressEventArgs : EventArgs {
	public float Progress {get; protected set;}

	public AESPlusProgressEventArgs(float progress){
		Progress = progress;
	}
}
/*
* AJ Savino
*/
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Diagnostics;

//Symmetric Encryption
public class AESPlus {
	protected const int KEY_SIZE = 256; //(128, 192, 256)
	protected const int BLOCK_SIZE = 128;
	protected const int CHUNK_SIZE = 4096; //4kb
	protected const string DEFAULT_FILE_FILTER = "*.*"; //All files

	public CipherMode Mode = CipherMode.CBC;
	public PaddingMode Padding = PaddingMode.PKCS7;
	public Encoding Encoding = Encoding.UTF8;
	public Boolean UsePlusCrypt = true;

	public delegate void OnProgressHandler(object sender, AESPlusProgressEventArgs evt);
	public event OnProgressHandler OnProgress;

	/// <summary>
	/// Specify a cancelToken from a CancellationTokenSource. Call Cancel() on the source
	/// </summary>
	public CancellationToken? CancelToken = null;
	
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="password">The password to use</param>
	public void EncryptDirectory(string directory, string password){
		EncryptDirectory(directory, password, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="password">The password to use</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void EncryptDirectory(string directory, string password, string fileFilter){
		EncryptDirectory(directory, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password), fileFilter);
	}
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	public void EncryptDirectory(string directory, byte[] key, byte[] iv){
		EncryptDirectory(directory, key, iv, null, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void EncryptDirectory(string directory, byte[] key, byte[] iv, string fileFilter){
		EncryptDirectory(directory, key, iv, null, fileFilter);
	}
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="salt">The salt value to use for "PlusCrypt"</param>
	public void EncryptDirectory(string directory, byte[] key, byte[] iv, byte[] salt){
		EncryptDirectory(directory, key, iv, salt, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Encrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="salt">The salt value to use for "PlusCrypt"</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void EncryptDirectory(string directory, byte[] key, byte[] iv, byte[] salt, string fileFilter){
		if (!Directory.Exists(directory)){
			throw new DirectoryNotFoundException();
		}
		EncryptFiles(new List<string>{directory}, key, iv, salt, fileFilter);
	}

	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="password">The password to use</param>
	public void DecryptDirectory(string directory, string password){
		DecryptDirectory(directory, password, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="password">The password to use</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void DecryptDirectory(string directory, string password, string fileFilter){
		DecryptDirectory(directory, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password), fileFilter);
	}
	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	public void DecryptDirectory(string directory, byte[] key, byte[] iv){
		DecryptDirectory(directory, key, iv, null, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void DecryptDirectory(string directory, byte[] key, byte[] iv, string fileFilter){
		DecryptDirectory(directory, key, iv, null, fileFilter);
	}
	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching *.*
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="salt">The salt value to use for "PlusCrypt"</param>
	public void DecryptDirectory(string directory, byte[] key, byte[] iv, byte[] salt){
		DecryptDirectory(directory, key, iv, salt, DEFAULT_FILE_FILTER);
	}
	/// <summary>
	/// Decrypts files in a directory including recursing subdirectories matching the fileFilter pattern
	/// </summary>
	/// <param name="directory">The directory to recurse</param>
	/// <param name="key">The byte array key to use</param>
	/// <param name="iv">The byte array initialization vector</param>
	/// <param name="salt">The salt value to use for "PlusCrypt"</param>
	/// <param name="fileFilter">What files to match. Example: *.*</param>
	public void DecryptDirectory(string directory, byte[] key, byte[] iv, byte[] salt, string fileFilter){
		if (!Directory.Exists(directory)){
			throw new DirectoryNotFoundException();
		}
		DecryptFiles(new List<string>{directory}, key, iv, salt, fileFilter);
	}

	public void EncryptFiles(List<string> fileNames, string password){
		EncryptFiles(fileNames, password, null);
	}
	public void EncryptFiles(List<string> fileNames, string password, string subDirFileFilter){
		EncryptFiles(fileNames, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password), subDirFileFilter);
	}
	public void EncryptFiles(List<string> fileNames, byte[] key, byte[] iv){
		EncryptFiles(fileNames, key, iv, null, null);
	}
	public void EncryptFiles(List<string> fileNames, byte[] key, byte[] iv, string subDirFileFilter){
		EncryptFiles(fileNames, key, iv, null, subDirFileFilter);
	}
	public void EncryptFiles(List<string> fileNames, byte[] key, byte[] iv, byte[] salt){
		EncryptFiles(fileNames, key, iv, salt, null);
	}
	public void EncryptFiles(List<string> fileNames, byte[] key, byte[] iv, byte[] salt, string subDirFileFilter){
		List<string> allFileNames = FindFiles(fileNames, subDirFileFilter);
		Parallel.ForEach(allFileNames, (fileName) => {
			EncryptFile(fileName, key, iv, salt);
		});
	}

	public void DecryptFiles(List<string> fileNames, string password){
		DecryptFiles(fileNames, password, null);
	}
	public void DecryptFiles(List<string> fileNames, string password, string subDirFileFilter){
		DecryptFiles(fileNames, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password), subDirFileFilter);
	}
	public void DecryptFiles(List<string> fileNames, byte[] key, byte[] iv){
		DecryptFiles(fileNames, key, iv, null, null);
	}
	public void DecryptFiles(List<string> fileNames, byte[] key, byte[] iv, string subDirFileFilter){
		DecryptFiles(fileNames, key, iv, null, subDirFileFilter);
	}
	public void DecryptFiles(List<string> fileNames, byte[] key, byte[] iv, byte[] salt){
		DecryptFiles(fileNames, key, iv, salt, null);
	}
	public void DecryptFiles(List<string> fileNames, byte[] key, byte[] iv, byte[] salt, string subDirFileFilter){
		List<string> allFileNames = FindFiles(fileNames, subDirFileFilter);
		Parallel.ForEach(allFileNames, (fileName) => {
			DecryptFile(fileName, key, iv, salt);
		});
	}

	public void EncryptFile(string fileName, string password){
		EncryptFile(fileName, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password));
	}
	public void EncryptFile(string fileName, byte[] key, byte[] iv){
		EncryptFile(fileName, key, iv, null);
	}
	public void EncryptFile(string fileName, byte[] key, byte[] iv, byte[] salt){
		if (!File.Exists(fileName)){
			throw new FileNotFoundException();
		}
		string fileNameEncrypted = fileName + ".encrypted";
		try {
			using (FileStream inputFS = new FileStream(fileName, FileMode.Open, FileAccess.Read)){
				using (FileStream outputFS = new FileStream(fileNameEncrypted, FileMode.Create, FileAccess.Write)){
					EncryptStream(inputFS, outputFS, key, iv, salt);
				}
			}
			ReplaceFile(fileName, fileNameEncrypted);
		} finally {
			File.Delete(fileNameEncrypted);
		}
	}

	public void DecryptFile(string fileName, string password){
		DecryptFile(fileName, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password));
	}
	public void DecryptFile(string fileName, byte[] key, byte[] iv){
		DecryptFile(fileName, key, iv, null);
	}
	public void DecryptFile(string fileName, byte[] key, byte[] iv, byte[] salt){
		if (!File.Exists(fileName)){
			throw new FileNotFoundException();
		}
		string fileNameDecrypted = fileName + ".decrypted";
		try {
			using (FileStream inputFS = new FileStream(fileName, FileMode.Open, FileAccess.Read)){
				using (FileStream outputFS = new FileStream(fileNameDecrypted, FileMode.Create, FileAccess.Write)){
					DecryptStream(inputFS, outputFS, key, iv, salt);
				}
			}
			ReplaceFile(fileName, fileNameDecrypted);
		} finally {
			File.Delete(fileNameDecrypted);
		}
	}

	public string EncryptString(string input, string password){
		return EncryptString(input, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password));
	}
	public string EncryptString(string input, byte[] key, byte[] iv){
		return EncryptString(input, key, iv, null);
	}
	public string EncryptString(string input, byte[] key, byte[] iv, byte[] salt){
		using (MemoryStream inputMS = new MemoryStream()){
			byte[] inputBytes = Encoding.GetBytes(input);
			inputMS.Write(inputBytes, 0, inputBytes.Length);
			inputMS.Position = 0;
			using (MemoryStream outputMS = new MemoryStream()){
				EncryptStream(inputMS, outputMS, key, iv, salt);
				return Convert.ToBase64String(outputMS.ToArray());
			}
		}
	}

	public string DecryptString(string input, string password){
		return DecryptString(input, ComputeKey(password), ComputeIV(password), Encoding.GetBytes(password));
	}
	public string DecryptString(string input, byte[] key, byte[] iv){
		return DecryptString(input, key, iv, null);
	}
	public string DecryptString(string input, byte[] key, byte[] iv, byte[] salt){
		using (MemoryStream inputMS = new MemoryStream()){
			byte[] inputBytes = Convert.FromBase64String(input);
			inputMS.Write(inputBytes, 0, inputBytes.Length);
			inputMS.Position = 0;
			using (MemoryStream outputMS = new MemoryStream()){
				DecryptStream(inputMS, outputMS, key, iv, salt);
				return Encoding.GetString(outputMS.ToArray());
			}
		}
	}

	public void EncryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv){
		EncryptStream(inputStream, outputStream, key, iv, null);
	}
	public void EncryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv, byte[] salt){
		using (RijndaelManaged aes = new RijndaelManaged()){
			CryptoStream cs = null;
			try {
				aes.Mode = Mode;
				aes.Padding = Padding;
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
					if (UsePlusCrypt && salt != null){
						PlusCrypt(buffer, key, salt, (byte)(offset % 0xFF));
					}
					cs.Write(buffer, 0, readSize);
					offset++;
					if (OnProgress != null){
						//OnProgress(null, new AESPlusProgressEventArgs((float)inputStream.Position / (float)inputStream.Length));
					}
				}
				cs.FlushFinalBlock();
			} finally {
				aes.Dispose();
			}
		}
	}

	public void DecryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv){
		DecryptStream(inputStream, outputStream, key, iv, null);
	}
	public void DecryptStream(Stream inputStream, Stream outputStream, byte[] key, byte[] iv, byte[] salt){
		using (RijndaelManaged aes = new RijndaelManaged()){
			CryptoStream cs = null;
			try {
				aes.Mode = Mode;
				aes.Padding = Padding;
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
					if (UsePlusCrypt && salt != null){
						PlusCrypt(buffer, key, salt, (byte)(offset % 0xFF));
					}
					outputStream.Write(buffer, 0, readSize);
					offset++;
					if (OnProgress != null){
						//OnProgress(null, new AESPlusProgressEventArgs((float)inputStream.Position / (float)inputStream.Length));
					}
				}
			} finally {
				aes.Dispose();
			}
		}
	}
	
	public byte[] StringToByteArray(string hex) {
		return Enumerable.Range(0, hex.Length)
						 .Where(x => x % 2 == 0)
						 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
						 .ToArray();
	}
	
	private byte[] ComputeIV(String password){
		SHA256 sha256 = SHA256.Create();
		byte[] iv = sha256.ComputeHash(Encoding.GetBytes(password));
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

	private byte[] ComputeKey(String password){
		SHA256 sha256 = SHA256.Create();
		byte[] newKey = sha256.ComputeHash(Encoding.GetBytes(password));
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
	private byte[] PlusCrypt(byte[] buffer, byte[] key, byte[] salt, byte offset){
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

	protected List<string> FindFiles(string directory){
		return FindFiles(new List<string>(){directory}, DEFAULT_FILE_FILTER);
	}
	protected List<string> FindFiles(string directory, string subDirFileFilter){
		return FindFiles(new List<string>(){directory}, subDirFileFilter);
	}
	protected List<string> FindFiles(List<string> fileNames){
		return FindFiles(fileNames, DEFAULT_FILE_FILTER);
	}
	protected List<string> FindFiles(List<string> fileNames, string subDirFileFilter){
		List<string> allFileNames = new List<string>();

		int fileNamesLen = fileNames.Count;
		for (int i = 0; i < fileNamesLen; i++){
			string fileName = fileNames[i];
			if (allFileNames.Contains(fileName)){
				continue;
			}
			if (Directory.Exists(fileName)){
				if (string.IsNullOrEmpty(subDirFileFilter)){ //No subDirectories
					continue;
				}
				List<string> subFiles = Directory.GetFiles(fileName, subDirFileFilter, SearchOption.AllDirectories).ToList<string>();
				allFileNames.AddRange(FindFiles(subFiles)); //Recurse
			} else if (File.Exists(fileName)){
				allFileNames.Add(fileName);
			}
		}

		return allFileNames;
	}

	protected void ReplaceFile(string fileToReplace, string replaceWithFile){
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
}

public class AESPlusProgressEventArgs : EventArgs {
	public String CurrentFileName {get; protected set;}
	public int CurrentFileNumber {get; protected set;}
	public int TotalFiles {get; protected set;}
	public float CurrentFileProgress {get; protected set;}
}
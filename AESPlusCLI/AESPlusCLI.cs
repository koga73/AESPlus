/*
* AJ Savino
*/
using System;
using System.IO;
using System.Collections.Generic;
using System.Reflection;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace AESPlusCLI {
	class AESPlusCLI {
		protected static int _lastProgress = 0;

		static void Main(string[] args){
			bool showHelp = false;

			bool encrypt = true;
			List<string> fileNames = new List<string>();
			string pass = null;
			
            string arg;
			int argsLen = args.Length;
			switch (argsLen){
				case 0:
					showHelp = true;
					break;
				case 1:
					arg = args[0].ToLower();
					if (arg == "?" || arg == "/?" || arg == "help" || arg == "/help"){
						showHelp = true;
					}
					break;
				case 3:
					arg = args[0].ToLower();
					if (arg == "/d" || arg == "/decrypt" || arg == "/e" || arg == "/encrypt"){
						if (arg == "/d" || arg == "/decrypt"){
							encrypt = false;
						}
						fileNames.Add(args[1]);
						pass = args[2];
					}
					break;
				default:
					for (int i = 0; i < argsLen; i++){
						switch (args[i].ToLower()){
							case "/e":
							case "/encrypt":
								i++;
								encrypt = true;
								break;
							case "/d":
							case "/decrypt":
								i++;
								encrypt = false;
								break;
							case "/f":
							case "/file":
								i++;
								fileNames.Add(args[i]);
								break;
							case "/p":
							case "/pass":
								i++;
								pass = args[i];
								break;
						}
					}
					break;
			}

			LogMessage();
			Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            string name = fvi.ProductName;
            string version = fvi.FileVersion;
            int index = fvi.FileVersion.LastIndexOf(".");
            version = version.Substring(0, index);
			LogMessage(name + " v" + version, ConsoleColor.Cyan);
            if (showHelp){ //Help
				if (showHelp){
					string author = fvi.Comments;
					LogMessage("By: " + author, ConsoleColor.Red);
                }
				LogMessage("Encrypts / Decrypts a file using AES-256 along with proprietary encryption");
                LogMessage();
				LogMessage("AESPlus [filename] [filename] [filename] ...");
                LogMessage("AESPlus [/e|/d] [filename] [password]", ConsoleColor.DarkGray);
                LogMessage("AESPlus [/e|/d] /f [filename] /p [password]", ConsoleColor.DarkGray);
                LogMessage();
                LogMessage("/e Encrypt file");
				LogMessage("/d Decrypt file");
                LogMessage("/f Filename to encrypt / decrypt");
                LogMessage("/p Password");
                LogMessage();
                return;
            } else if (fileNames.Count == 0 || string.IsNullOrEmpty(pass)){ //Treat each argument as a fileName. Activate wizard
				fileNames.AddRange(args);
				int fileNamesLen = fileNames.Count;
				for (int i = 0; i < fileNamesLen; i++){
					string fileName = fileNames[i];
					if (Directory.Exists(fileName)){
						fileNames.Remove(fileName);
						i--;
						string[] files = Directory.GetFiles(fileName, "*.*", SearchOption.AllDirectories);
						foreach (string file in files){
							if (!fileNames.Contains(file)){
								fileNames.Add(file);
							}
						}
					}
				}
				LogMessage(fileNames.Count + " files");
				LogMessage();
				string letter;
				do {
					LogMessage("Type a letter to select:");
					LogMessage("[E]ncrypt");
					LogMessage("[D]ecrypt");
					letter = Console.ReadLine().ToLower();
					LogMessage();
				} while (letter != "e" && letter != "d");
				if (letter == "e"){
					encrypt = true;
				} else if (letter == "d"){
					encrypt = false;
				}
				LogMessage("Type the password to use:"); //Code below hides password input
				pass = "";
				ConsoleKeyInfo newKey;
				while (!Console.KeyAvailable){
					Thread.Sleep(250); //Wait for key
				}
				while ((newKey = Console.ReadKey(true)).Key != ConsoleKey.Enter){
					char keyChar = newKey.KeyChar;
					if (keyChar >= 32 && keyChar <= 126){ //Valid chars
						pass += keyChar;
					}
					if (keyChar == 8){ //Backspace
						if (pass.Length > 0){
							pass = pass.Substring(0, pass.Length - 1);
						}
					}
				}
				LogMessage();
			}

			CancellationTokenSource cancelSource = new CancellationTokenSource();
			AESPlus.OnProgress += Handler_AESPlus_Progress;
			foreach (string fileName in fileNames){
				if (cancelSource.IsCancellationRequested){
					break;
				}
				_lastProgress = 0;
				Task task = null;
				if (encrypt){
					LogMessage("Encrypting: " + fileName, ConsoleColor.DarkGreen);
					LogMessage("Press ESC to cancel", ConsoleColor.DarkYellow);
					LogMessage();
					task = Task.Factory.StartNew(() => {
						AESPlus.CancelToken = cancelSource.Token;
						AESPlus.EncryptFile(fileName, pass);
					}, cancelSource.Token);
				} else {
					LogMessage("Decrypting: " + fileName, ConsoleColor.DarkGreen);
					LogMessage("Press ESC to cancel", ConsoleColor.DarkYellow);
					LogMessage();
					task = Task.Factory.StartNew(() => {
						AESPlus.CancelToken = cancelSource.Token;
						AESPlus.DecryptFile(fileName, pass);
					}, cancelSource.Token);
				}
				while (!task.IsCompleted && !task.IsCanceled && !task.IsFaulted){
					if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape){
						cancelSource.Cancel();
					}
				}
				if (task.IsCompleted && !task.IsFaulted && !task.IsCanceled){
					LogMessage("Complete!", ConsoleColor.Green);
				} else if (task.IsFaulted){
					try {
						throw task.Exception.InnerException;
					} catch (CryptographicException ex){
						if (encrypt){
							LogException(ex, false);
						} else {
							LogException(new Exception("AES failed. Ensure file is encrypted and key is correct."), false);
						}
					} catch (Exception ex){
						LogException(ex, false);
					}
				} else if (task.IsCanceled){
					LogMessage("Aborted!", ConsoleColor.Red);
				}
				LogMessage("", ConsoleColor.White);
			}
		}

		protected static void Handler_AESPlus_Progress(object sender, AESPlusProgressEventArgs evt){
			int progress = (int)Math.Floor(evt.Progress * 100);
			if (progress != _lastProgress){
				_lastProgress = progress;
				Console.SetCursorPosition(Console.CursorLeft, Console.CursorTop - 1);
				LogMessage("Progress: " + progress + "%", ConsoleColor.Yellow);
			}
		}

		public static void LogException(Exception ex, bool isFatal = true){
            if (isFatal){
                LogMessage("*** FATAL ERROR ***\n" + ex.Message, ConsoleColor.Red);
            } else {
                LogMessage("ERROR: " + ex.Message, ConsoleColor.Red);
            }
        }

        public static void LogMessage(string msg = "", ConsoleColor color = ConsoleColor.White){
            Console.ResetColor();
            if (color != ConsoleColor.White){
                Console.ForegroundColor = color;
            }
            Console.WriteLine(msg);
        }
	}
}
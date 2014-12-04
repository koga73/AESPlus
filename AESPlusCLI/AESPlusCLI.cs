/*
* AJ Savino
*/
using System;
using System.Reflection;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace AESPlusCLI {
	class AESPlusCLI {
		protected static int _lastProgress = 0;

		static void Main(string[] args){
			bool encrypt = true;
			string fileName = null;
			string pass = null;

			bool showHelp = false;
            int argsLen = args.Length;
			if (argsLen == 1){
                string arg = args[0].ToLower();
                if (arg == "?" || arg == "/?" || arg == "help" || arg == "/help"){
					showHelp = true;
				}
			} else if (argsLen == 3){
				if (args[0] == "/d" || args[0] == "/decrypt"){
					encrypt = false;
				}
				fileName = args[1];
				pass = args[2];
			} else {
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
							fileName = args[i];
							break;
						case "/p":
						case "/pass":
							i++;
							pass = args[i];
							break;
					}
				}
			}
            
			LogMessage();
			Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            string name = fvi.ProductName;
            string version = fvi.FileVersion;
            int index = fvi.FileVersion.LastIndexOf(".");
            version = version.Substring(0, index);
			LogMessage(name + " v" + version, ConsoleColor.Cyan);
            if (string.IsNullOrEmpty(fileName) || string.IsNullOrEmpty(pass) || showHelp){
				if (showHelp){
					string author = fvi.Comments;
					LogMessage("By: " + author, ConsoleColor.Red);
                }
				LogMessage("Encrypts / Decrypts a file using AES-256 along with proprietary encryption");
                LogMessage();
                LogMessage("AESPlus [/e|/d] [filename] [password]");
                LogMessage("AESPlus [/e|/d] /f [filename] /p [password]", ConsoleColor.DarkGray);
                LogMessage();
                LogMessage("/e Encrypt file");
				LogMessage("/d Decrypt file");
                LogMessage("/f Filename to encrypt / decrypt");
                LogMessage("/p Password");
                LogMessage();
                return;
            }

			_lastProgress = 0;
			AESPlus.OnProgress += Handler_AESPlus_Progress;
			CancellationTokenSource cancelSource = new CancellationTokenSource();
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
						LogException(ex);
					} else {
						LogException(new Exception("AES failed. Ensure file is encrypted and key is correct."));
					}
				} catch (Exception ex){
					LogException(ex);
				}
			} else if (task.IsCanceled){
				LogMessage("Aborted!", ConsoleColor.Red);
			}
            LogMessage("", ConsoleColor.White);
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
                LogMessage("ERROR: " + ex.Message, ConsoleColor.Yellow);
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
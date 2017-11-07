using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Forms;

namespace AESPlusGUI
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		public MainWindow()
		{
			InitializeComponent();
		}

		private void btnChoose_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog fileDialog = new OpenFileDialog();
			fileDialog.Filter = "All Files (*.*)|*.*";
			fileDialog.Multiselect = true;
			fileDialog.Title = "Select file(s) to encrypt/decrypt";
			
			DialogResult fileResult = fileDialog.ShowDialog();
			if (fileResult == System.Windows.Forms.DialogResult.OK)
			{
				Debug.Print(fileDialog.FileNames.ToString());
			}
		}
	}
}
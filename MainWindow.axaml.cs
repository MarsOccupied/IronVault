using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using IronVault.Services;

namespace IronVault;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<string> _items = new();
    private readonly CryptoService _crypto = new();
    private string? _lastOutputPath;

    public MainWindow()
    {
        InitializeComponent();
        ItemsList.ItemsSource = _items;

        DropZone.AddHandler(DragDrop.DragOverEvent, OnDragOver, RoutingStrategies.Tunnel);
        DropZone.AddHandler(DragDrop.DropEvent, OnDrop, RoutingStrategies.Tunnel);

        ClearButton.Click += (_, _) => { _items.Clear(); SetStatus("Queue cleared."); };
        BrowseKeyfileButton.Click += OnBrowseKeyfileAsync;
        EncryptButton.Click += OnRunAsync;
        OpenOutputButton.Click += OnOpenOutput;
    }

    private void OnDragOver(object? sender, DragEventArgs e)
    {
        var data = e.Data;
        if (data?.Contains(DataFormats.Files) == true)
        {
            e.DragEffects = DragDropEffects.Copy;
        }
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        var data = e.Data;
        if (data is null || !data.Contains(DataFormats.Files))
            return;

        var files = data.GetFiles();
        if (files is null)
            return;

        foreach (var item in files)
        {
            var path = item.Path?.LocalPath;
            if (!string.IsNullOrWhiteSpace(path) && !_items.Contains(path))
            {
                _items.Add(path);
            }
        }

        SetStatus($"Added {_items.Count} item(s).");
    }

    private async void OnBrowseKeyfileAsync(object? sender, RoutedEventArgs e)
    {
        var result = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            AllowMultiple = false,
            Title = "Select keyfile"
        });

        var path = result?.FirstOrDefault()?.Path?.LocalPath;
        if (!string.IsNullOrWhiteSpace(path))
        {
            KeyfileBox.Text = path;
        }
    }

    private async void OnRunAsync(object? sender, RoutedEventArgs e)
    {
        if (_items.Count == 0)
        {
            SetStatus("Please add at least one file or folder.");
            return;
        }

        var password = PasswordBox.Text ?? string.Empty;
        if (string.IsNullOrWhiteSpace(password))
        {
            SetStatus("Password is required.");
            return;
        }

        await RunCryptoAsync(password);
    }

    private async Task RunCryptoAsync(string password)
    {
        SetBusy(true);
        var progress = new Progress<double>(value => ProgressBar.Value = value);
        ProgressBar.Value = 0;
        _lastOutputPath = null;
        OpenOutputButton.IsEnabled = false;

        try
        {
            if (EncryptRadio.IsChecked == true)
            {
                SetStatus("Encrypting...");
                var output = await _crypto.EncryptAsync(_items.ToList(), password, KeyfileBox.Text, progress);
                _lastOutputPath = output;
                SetStatus($"Encrypted to {output}");
            }
            else
            {
                if (_items.Count != 1)
                {
                    SetStatus("Decrypt expects exactly one .vault file.");
                    return;
                }

                SetStatus("Decrypting...");
                var output = await _crypto.DecryptAsync(_items[0], password, KeyfileBox.Text, progress);
                _lastOutputPath = output;
                SetStatus($"Decrypted into {output}");
            }

            OpenOutputButton.IsEnabled = _lastOutputPath is not null;
        }
        catch (Exception ex)
        {
            SetStatus($"Error: {ex.Message}");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void OnOpenOutput(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastOutputPath))
            return;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = _lastOutputPath,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            SetStatus($"Unable to open: {ex.Message}");
        }
    }

    private void SetBusy(bool busy)
    {
        EncryptButton.IsEnabled = !busy;
        BrowseKeyfileButton.IsEnabled = !busy;
        ClearButton.IsEnabled = !busy;
        EncryptRadio.IsEnabled = !busy;
        DecryptRadio.IsEnabled = !busy;
    }

    private void SetStatus(string text)
    {
        StatusText.Text = text;
    }
}
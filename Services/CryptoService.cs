using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace IronVault.Services;

/// <summary>
/// Implements AES-256-GCM encryption with PBKDF2 key derivation and simple
/// container format for packing multiple files/folders into a single .vault.
/// </summary>
public sealed class CryptoService
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32; // AES-256
    private const int KdfIterations = 200_000;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("IVLT");
    private const byte Version = 1;

    public async Task<string> EncryptAsync(
        IReadOnlyList<string> inputs,
        string password,
        string? keyFilePath,
        IProgress<double>? progress = null)
    {
        if (inputs.Count == 0)
            throw new InvalidOperationException("No files or folders provided.");

        progress?.Report(0.05);

        var tempZip = Path.Combine(Path.GetTempPath(), $"ironvault-{Guid.NewGuid():N}.zip");
        try
        {
            PackToZip(inputs, tempZip);
            progress?.Report(0.35);

            var plainBytes = await File.ReadAllBytesAsync(tempZip);
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);

            var keyMaterial = await CombinePasswordAndKeyfileAsync(password, keyFilePath);
            var key = DeriveKey(keyMaterial, salt);

            var cipher = new byte[plainBytes.Length];
            var tag = new byte[TagSize];

            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, plainBytes, cipher, tag);
            }

            progress?.Report(0.7);

            var outputPath = BuildOutputPath(inputs, ".vault");
            using (var fs = File.Open(outputPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                fs.Write(Magic);
                fs.WriteByte(Version);
                fs.Write(salt);
                fs.Write(nonce);
                fs.Write(tag);
                fs.Write(cipher);
            }

            progress?.Report(1.0);
            return outputPath;
        }
        finally
        {
            if (File.Exists(tempZip))
            {
                File.Delete(tempZip);
            }
        }
    }

    public async Task<string> DecryptAsync(
        string vaultPath,
        string password,
        string? keyFilePath,
        IProgress<double>? progress = null)
    {
        if (!File.Exists(vaultPath))
            throw new FileNotFoundException("Vault not found.", vaultPath);

        progress?.Report(0.05);

        var data = await File.ReadAllBytesAsync(vaultPath);
        var offset = 0;

        if (data.Length < Magic.Length + 1 + SaltSize + NonceSize + TagSize)
            throw new InvalidDataException("Vault file is too small or corrupted.");

        if (!data.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Invalid vault header.");
        offset += Magic.Length;

        var version = data[offset++];
        if (version != Version)
            throw new NotSupportedException($"Unsupported vault version: {version}");

        var salt = data.AsSpan(offset, SaltSize).ToArray();
        offset += SaltSize;
        var nonce = data.AsSpan(offset, NonceSize).ToArray();
        offset += NonceSize;
        var tag = data.AsSpan(offset, TagSize).ToArray();
        offset += TagSize;

        var cipher = data.AsSpan(offset).ToArray();
        var plain = new byte[cipher.Length];

        var keyMaterial = await CombinePasswordAndKeyfileAsync(password, keyFilePath);
        var key = DeriveKey(keyMaterial, salt);

        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Decrypt(nonce, cipher, tag, plain);
        }

        progress?.Report(0.65);

        var tempZip = Path.Combine(Path.GetTempPath(), $"ironvault-{Guid.NewGuid():N}.zip");
        await File.WriteAllBytesAsync(tempZip, plain);

        var outputDir = BuildOutputPathForExtraction(vaultPath);
        ZipFile.ExtractToDirectory(tempZip, outputDir, overwriteFiles: true);

        progress?.Report(1.0);
        File.Delete(tempZip);
        return outputDir;
    }

    private static async Task<byte[]> CombinePasswordAndKeyfileAsync(string password, string? keyFilePath)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        if (string.IsNullOrWhiteSpace(keyFilePath) || !File.Exists(keyFilePath))
            return passwordBytes;

        var keyBytes = await File.ReadAllBytesAsync(keyFilePath);
        return passwordBytes.Concat(keyBytes).ToArray();
    }

    private static byte[] DeriveKey(byte[] passwordBytes, byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(passwordBytes, salt, KdfIterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(KeySize);
    }

    private static void PackToZip(IReadOnlyList<string> inputs, string zipPath)
    {
        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);
        foreach (var path in inputs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(path))
            {
                AddFile(archive, path, Path.GetFileName(path));
            }
            else if (Directory.Exists(path))
            {
                AddDirectory(archive, path, Path.GetFileName(path));
            }
            else
            {
                throw new FileNotFoundException("Input not found.", path);
            }
        }
    }

    private static void AddFile(ZipArchive archive, string filePath, string entryPath)
    {
        archive.CreateEntryFromFile(filePath, entryPath, CompressionLevel.Optimal);
    }

    private static void AddDirectory(ZipArchive archive, string directoryPath, string prefix)
    {
        foreach (var file in Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(directoryPath, file);
            var entryName = Path.Combine(prefix, relative).Replace('\\', '/');
            AddFile(archive, file, entryName);
        }
    }

    private static string BuildOutputPath(IReadOnlyList<string> inputs, string extension)
    {
        string baseName;
        if (inputs.Count == 1)
        {
            var first = inputs[0];
            var name = File.Exists(first) ? Path.GetFileName(first) : Path.GetFileName(first.TrimEnd(Path.DirectorySeparatorChar));
            baseName = name;
        }
        else
        {
            baseName = "Archive";
        }

        var directory = Path.GetDirectoryName(inputs[0]) ?? Directory.GetCurrentDirectory();
        var target = Path.Combine(directory, $"{baseName}{extension}");
        return EnsureUnique(target);
    }

    private static string BuildOutputPathForExtraction(string vaultPath)
    {
        var dir = Path.GetDirectoryName(vaultPath) ?? Directory.GetCurrentDirectory();
        var name = Path.GetFileNameWithoutExtension(vaultPath);
        var target = Path.Combine(dir, $"{name}_extracted");
        return EnsureUnique(target);
    }

    private static string EnsureUnique(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            return path;

        var directory = Path.GetDirectoryName(path) ?? Directory.GetCurrentDirectory();
        var name = Path.GetFileNameWithoutExtension(path);
        var ext = Path.GetExtension(path);
        var counter = 1;
        while (true)
        {
            var candidate = Path.Combine(directory, $"{name} ({counter}){ext}");
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
                return candidate;
            counter++;
        }
    }
}


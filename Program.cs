using System.Collections;
using System.Globalization;
using CommandLine;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ZigbeeOtaExtractor;

public static class Program
{
    private static readonly Dictionary<string, FileStream> Files = new();
    private static readonly Dictionary<string, BitArray> BitArrays = new();

    [UsedImplicitly(ImplicitUseKindFlags.Assign, ImplicitUseTargetFlags.WithMembers)]
    private class Options
    {
        [Value(0, Required = true, HelpText = "Input file(s) (Wireshark JSON)")]
        public required IEnumerable<string> InputFiles { get; init; }
    }

    public static async Task Main(string[] args)
    {
        var options = Parser.Default.ParseArguments<Options>(args).Value;
        if (options == null) return;

        var jsonSerializer = new JsonSerializer();
        
        foreach (var jsonFilename in options.InputFiles)
        {
            Console.WriteLine($"Reading file {jsonFilename}...");
            await using var file = File.OpenRead(jsonFilename);
            using var streamReader = new StreamReader(file);
            await using var jsonReader = new JsonTextReader(streamReader);
 
            while(await jsonReader.ReadAsync())
            {
                if (jsonReader.TokenType != JsonToken.StartObject) continue;

                var node = jsonSerializer.Deserialize<JObject>(jsonReader);
                var zcl = node?["_source"]?["layers"]?["zbee_zcl"];

                if (zcl == null) continue;

                if (!int.TryParse(zcl["zbee_zcl_general.ota.cmd.srv_tx.id"]?.Value<string>()?.Substring(2),
                        NumberStyles.HexNumber, null, out var commandId)) continue;
                if (commandId == 0x02 /* Query Next Image Response */)
                {
                    var payload = zcl["Payload"]!;

                    if (!int.TryParse(payload["zbee_zcl_general.ota.image.size"]?.Value<string>(),
                            out var size)) continue;
                    var filename = ParseFilename(payload);

                    Console.WriteLine($"Found image response for {filename}");

                    if (!Files.ContainsKey(filename))
                    {
                        var fs = new FileStream(filename, FileMode.Create, FileAccess.Write, FileShare.None);
                        fs.SetLength(size);

                        Files.Add(filename, fs);
                        BitArrays.Add(filename, new BitArray(size, false));
                    }
                }
                else if (commandId == 0x05 /* Image Block Response */)
                {
                    var payload = zcl["Payload"]!;
                    var filename = ParseFilename(payload);

                    if (Files.TryGetValue(filename, out var fs))
                    {
                        var offset = int.Parse(payload["zbee_zcl_general.ota.file.offset"]?.Value<string>()!);
                        var size = int.Parse(payload["zbee_zcl_general.ota.data_size"]?.Value<string>()!);
                        var dataStr = payload["zbee_zcl_general.ota.image.data"]?.Value<string>()?.Replace(":", "")!;
                        var data = Convert.FromHexString(dataStr);

                        fs.Seek(offset, SeekOrigin.Begin);
                        fs.Write(data, 0, size);

                        var bitArray = BitArrays[filename];
                        for (int i = offset; i < offset + size; i++)
                        {
                            bitArray[i] = true;
                        }
                    }
                }
            }
        }

        foreach (var file in Files)
        {
            await file.Value.DisposeAsync();
        }

        foreach (var entry in BitArrays)
        {
            var array = entry.Value;
            var size = array.Count;
            var completedBytes = 0;

            for (int i = 0; i < size; i++)
            {
                if (array[i])
                {
                    completedBytes++;
                }
            }

            var fg = Console.ForegroundColor;
            if (completedBytes == size)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("SUCCESS! ");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("FAIL! ");
            }
            Console.ForegroundColor = fg;
            
            Console.WriteLine($"File {entry.Key}: {(double)completedBytes / size * 100}% complete");
        }
    }

    private static string ParseFilename(JToken payload)
    {
        var manufacturer = payload["zbee_zcl_general.ota.manufacturer_code"]?.Value<string>();
        var type = payload["zbee_zcl_general.ota.image.type"]?.Value<string>();
        var version = payload["zbee_zcl_general.ota.file.version"]?.Value<string>();

        return $"{manufacturer}_{type}_{version}.ota";
    }
}
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Net.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Exchange.WebServices.Data;

internal sealed class Program
{
    private static int Main(string[] args)
    {
        PatchEwsBuildVersion();

        var baseDir = AppContext.BaseDirectory;
        using var logger = new Logger(Path.Combine(baseDir, "export_ics.log"));
        try
        {
            var configPath = Path.Combine(baseDir, "config.cfg");
            var config = AppConfig.Load(configPath, logger);

            if (config.AllowUntrustedConnections)
            {
                // Allow connections to servers with untrusted SSL certificates (Autodiscover/EWS)
                ServicePointManager.ServerCertificateValidationCallback = 
                    (sender, certificate, chain, sslPolicyErrors) => true;
                logger.Info("Allowing untrusted SSL certificates for Autodiscover/EWS connections.");
            }

            var exporter = new CalendarExporter(config, logger);
            exporter.Run();
            return 0;
        }
        catch (Exception ex)
        {
            logger.Error($"Fatal error: {ex.Message}", ex);
            return 1;
        }
    }

    /// <summary>
    /// Workaround for EWS Managed API 2.2.0: the static constructor of
    /// <c>EwsUtilities</c> calls <c>FileVersionInfo.GetVersionInfo</c> with
    /// <c>Assembly.GetExecutingAssembly().Location</c>, which returns an empty
    /// string in single-file published apps (or certain modern .NET hosts),
    /// causing a <see cref="TypeInitializationException"/>.
    /// Pre-populate the lazy <c>BuildVersion</c> field via reflection so the
    /// problematic code path is never executed.
    /// </summary>
    private static void PatchEwsBuildVersion()
    {
        const BindingFlags staticFlags =
            BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public;
        const BindingFlags instanceFlags =
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;

        try
        {
            var ewsAssembly = typeof(ExchangeService).Assembly;
            var ewsUtilitiesType = ewsAssembly.GetType(
                "Microsoft.Exchange.WebServices.Data.EwsUtilities");

            if (ewsUtilitiesType == null)
            {
                Console.Error.WriteLine("[EWS-PATCH] EwsUtilities type not found.");
                return;
            }

            // Find the LazyMember<string> field by scanning all static fields.
            // The field is named "buildVersion" in the reference source, but we
            // match by type to be safe across different builds.
            FieldInfo? lazyField = null;
            foreach (var f in ewsUtilitiesType.GetFields(staticFlags))
            {
                var ft = f.FieldType;
                if (ft.IsGenericType &&
                    ft.GetGenericArguments() is { Length: 1 } ga &&
                    ga[0] == typeof(string) &&
                    ft.Name.StartsWith("LazyMember", StringComparison.Ordinal))
                {
                    lazyField = f;
                    break;
                }
            }

            if (lazyField == null)
            {
                Console.Error.WriteLine(
                    "[EWS-PATCH] LazyMember<string> field not found. Static fields: " +
                    string.Join(", ", ewsUtilitiesType.GetFields(staticFlags)
                        .Select(f => $"{f.Name}:{f.FieldType.Name}")));
                return;
            }

            var lazyObj = lazyField.GetValue(null);
            if (lazyObj == null)
            {
                Console.Error.WriteLine("[EWS-PATCH] LazyMember field value is null.");
                return;
            }

            var lazyType = lazyObj.GetType();

            // Scan instance fields of LazyMember<string> by type.
            FieldInfo? strField = null;
            FieldInfo? boolField = null;
            foreach (var f in lazyType.GetFields(instanceFlags))
            {
                if (f.FieldType == typeof(string) && strField == null)
                    strField = f;
                else if (f.FieldType == typeof(bool) && boolField == null)
                    boolField = f;
            }

            if (strField == null || boolField == null)
            {
                Console.Error.WriteLine(
                    "[EWS-PATCH] Could not find member/initialized fields. Instance fields: " +
                    string.Join(", ", lazyType.GetFields(instanceFlags)
                        .Select(f => $"{f.Name}:{f.FieldType.Name}")));
                return;
            }

            var version = ewsAssembly.GetName().Version?.ToString() ?? "2.2.0.0";
            boolField.SetValue(lazyObj, true);
            strField.SetValue(lazyObj, version);

            // Write back in case LazyMember<T> is a value type (struct).
            lazyField.SetValue(null, lazyObj);

            Console.Error.WriteLine($"[EWS-PATCH] Patched BuildVersion = \"{version}\".");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[EWS-PATCH] Failed: {ex}");
        }
    }
}

internal sealed record AppConfig(
    string AutodiscoverUrl,
    string EwsUrl,
    string InputFile,
    string OutputDirectory,
    string SuperAdmin,
    string SuperAdminPassword,
    int DaysAgo,
    int FileMaxSizeMb,
    bool AllowUntrustedConnections,
    TimeZoneInfo ExchangeTimeZone,
    IReadOnlyList<string> Mailboxes)
{
    public static AppConfig Load(string configPath, Logger logger)
    {
        if (!File.Exists(configPath))
        {
            throw new InvalidOperationException($"Config file not found: {configPath}");
        }

        var baseDir = Path.GetDirectoryName(configPath) ?? AppContext.BaseDirectory;
        var settings = ParseConfig(configPath);

        string GetSetting(string key, string fallback = "")
        {
            return settings.TryGetValue(key, out var value) ? value : fallback;
        }

        var autodiscoverUrl = GetSetting("audiscovery_url");
        var ewsUrl = GetSetting("ews_url");
        var inputFile = GetSetting("input_file", "input_mailboxes.txt");
        var outputDir = GetSetting("output_dir", "output");
        var superAdmin = GetSetting("superadmin");
        var superAdminPass = GetSetting("superadmin_pass");
        var daysAgo = ParseInt(GetSetting("days_ago"), "days_ago");
        var fileMaxSizeMb = ParseInt(GetSetting("file_max_size"), "file_max_size", 10);
        var allowUntrustedConnections = ParseBool(GetSetting("allow_untrusted_connections"), false);
        var exchangeTimeZone = ParseTimeZoneShift(GetSetting("exchange_timezone_shift", "+0"));

        if (string.IsNullOrWhiteSpace(superAdmin))
        {
            throw new InvalidOperationException("Parameter 'superadmin' is required.");
        }

        if (string.IsNullOrWhiteSpace(superAdminPass))
        {
            throw new InvalidOperationException("Parameter 'superadmin_pass' is required.");
        }

        if (!Path.IsPathRooted(inputFile))
        {
            inputFile = Path.Combine(baseDir, inputFile);
        }

        if (!File.Exists(inputFile))
        {
            throw new InvalidOperationException($"Input file not found: {inputFile}");
        }

        var mailboxes = File.ReadAllLines(inputFile)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (mailboxes.Count == 0)
        {
            throw new InvalidOperationException($"Input file is empty: {inputFile}");
        }

        if (!Path.IsPathRooted(outputDir))
        {
            outputDir = Path.Combine(baseDir, outputDir);
        }

        Directory.CreateDirectory(outputDir);
        logger.Info($"Using output directory: {outputDir}");

        if (daysAgo < 0)
        {
            throw new InvalidOperationException("Parameter 'days_ago' must be non-negative.");
        }

        if (fileMaxSizeMb <= 0)
        {
            logger.Warn("Parameter 'file_max_size' not set or invalid, defaulting to 10 MB.");
            fileMaxSizeMb = 10;
        }

        return new AppConfig(
            autodiscoverUrl,
            ewsUrl,
            inputFile,
            outputDir,
            superAdmin,
            superAdminPass,
            daysAgo,
            fileMaxSizeMb,
            allowUntrustedConnections,
            exchangeTimeZone,
            mailboxes);
    }

    private static Dictionary<string, string> ParseConfig(string path)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in File.ReadAllLines(path))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var separatorIndex = line.IndexOf('=');
            if (separatorIndex <= 0)
            {
                continue;
            }

            var key = line[..separatorIndex].Trim();
            var value = line[(separatorIndex + 1)..].Trim();
            if (!string.IsNullOrEmpty(key))
            {
                dict[key] = value;
            }
        }

        return dict;
    }

    private static int ParseInt(string value, string name, int defaultValue = -1)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            return parsed;
        }

        throw new InvalidOperationException($"Parameter '{name}' must be an integer value.");
    }

    private static bool ParseBool(string value, bool defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("1", StringComparison.Ordinal);
    }

    private static TimeZoneInfo ParseTimeZoneShift(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            value = "+0";
        }

        value = value.Trim();
        if (!value.StartsWith("+", StringComparison.Ordinal) && !value.StartsWith("-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Parameter 'exchange_timezone_shift' must start with '+' or '-' (e.g., +3 or -5).");
        }

        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var hours))
        {
            throw new InvalidOperationException($"Parameter 'exchange_timezone_shift' has invalid format: '{value}'. Expected format: +N or -N (e.g., +3 or -5).");
        }

        var tzName = hours >= 0 ? $"UTC+{hours}" : $"UTC{hours}";
        return TimeZoneInfo.CreateCustomTimeZone(tzName, TimeSpan.FromHours(hours), tzName, tzName);
    }
}

internal sealed class CalendarExporter
{
    private const int THREAD_COUNT = 4;

    private readonly AppConfig _config;
    private readonly Logger _logger;
    private readonly PropertySet _loadPropertySet;

    public CalendarExporter(AppConfig config, Logger logger)
    {
        _config = config;
        _logger = logger;
        _loadPropertySet = new PropertySet(
            BasePropertySet.FirstClassProperties,
            AppointmentSchema.MimeContent,
            AppointmentSchema.Organizer,
            AppointmentSchema.RequiredAttendees,
            AppointmentSchema.OptionalAttendees,
            AppointmentSchema.Resources,
            AppointmentSchema.AppointmentType,
            AppointmentSchema.ICalUid,
            AppointmentSchema.Start,
            AppointmentSchema.End,
            AppointmentSchema.FirstOccurrence,
            AppointmentSchema.LastOccurrence,
            AppointmentSchema.Recurrence)
        {
            RequestedBodyType = BodyType.Text
        };
    }

    public void Run()
    {
        var ewsUri = ResolveEwsUrl();
        var exchangeTimeZone = _config.ExchangeTimeZone;

        _logger.Info($"Resolved EWS endpoint: {ewsUri}");
        _logger.Info($"Using Exchange timezone: {exchangeTimeZone.DisplayName}");

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = THREAD_COUNT
        };

        Parallel.ForEach(_config.Mailboxes, parallelOptions, mailbox =>
        {
            using var scope = _logger.BeginMailboxScope(mailbox);
            try
            {
                ExportMailbox(ewsUri, exchangeTimeZone, mailbox);
            }
            catch (Exception ex)
            {
                _logger.Error(WithMailbox(mailbox, $"Failed to export mailbox: {ex.Message}"), ex);
            }
        });
    }

    private Uri ResolveEwsUrl()
    {
        if (!string.IsNullOrWhiteSpace(_config.AutodiscoverUrl))
        {
            try
            {
                var autodiscover = new AutodiscoverService(ExchangeVersion.Exchange2013)
                {
                    Credentials = new WebCredentials(_config.SuperAdmin, _config.SuperAdminPassword),
                    EnableScpLookup = false,
                };

                autodiscover.Url = new Uri(_config.AutodiscoverUrl);
                _logger.Info($"Trying autodiscover at {_config.AutodiscoverUrl}");
                var response = autodiscover.GetUserSettings(
                    _config.SuperAdmin,
                    new[]
                    {
                        UserSettingName.InternalEwsUrl,
                        UserSettingName.ExternalEwsUrl
                    });

                if (response.ErrorCode == AutodiscoverErrorCode.NoError)
                {
                    var urlCandidate =
                        response.Settings.TryGetValue(UserSettingName.InternalEwsUrl, out var internalUrl)
                            ? internalUrl as string
                            : response.Settings.TryGetValue(UserSettingName.ExternalEwsUrl, out var externalUrl)
                                ? externalUrl as string
                                : null;

                    if (!string.IsNullOrWhiteSpace(urlCandidate))
                    {
                        _logger.Info($"Autodiscover returned EWS url: {urlCandidate}");
                        return new Uri(urlCandidate);
                    }
                }

                _logger.Warn("Autodiscover did not return a usable EWS url, falling back to configured ews_url.");
            }
            catch (Exception ex)
            {
                _logger.Warn($"Autodiscover failed: {ex.Message}. Falling back to configured ews_url.");
            }
        }

        if (string.IsNullOrWhiteSpace(_config.EwsUrl))
        {
            throw new InvalidOperationException("Neither autodiscovery nor ews_url provided a valid endpoint.");
        }

        return new Uri(_config.EwsUrl);
    }

    private ExchangeService CreateService(Uri ewsUri, TimeZoneInfo exchangeTimeZone)
    {
        return new ExchangeService(ExchangeVersion.Exchange2013, exchangeTimeZone)
        {
            Credentials = new WebCredentials(_config.SuperAdmin, _config.SuperAdminPassword),
            Url = ewsUri,
            TraceEnabled = false,
        };
    }

    private void ExportMailbox(Uri ewsUri, TimeZoneInfo exchangeTimeZone, string mailbox)
    {
        _logger.Info(WithMailbox(mailbox, "Exporting mailbox"));
        var masterCache = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var startDate = DateTime.UtcNow.AddDays(-_config.DaysAgo);
        var endDate = DateTime.UtcNow.AddYears(1);

        var chunk = TimeSpan.FromDays(30);

        // Build all time ranges up-front so chunks can be processed in parallel
        var timeRanges = new List<(DateTime Start, DateTime End)>();
        var currentStart = startDate;
        while (currentStart < endDate)
        {
            var currentEnd = currentStart.Add(chunk);
            if (currentEnd > endDate)
            {
                currentEnd = endDate;
            }

            timeRanges.Add((currentStart, currentEnd));
            currentStart = currentEnd;
        }

        _logger.Info(WithMailbox(mailbox, $"Reading calendar in {timeRanges.Count} chunks using up to {THREAD_COUNT} threads"));

        // Each thread gets its own ExchangeService (EWS objects are not thread-safe)
        var chunkResults = new ConcurrentBag<List<Appointment>>();
        var chunkParallelOptions = new ParallelOptions { MaxDegreeOfParallelism = THREAD_COUNT };

        Parallel.ForEach(timeRanges, chunkParallelOptions, range =>
        {
            try
            {
                var threadService = CreateService(ewsUri, exchangeTimeZone);
                var calendar = BindCalendarFolder(threadService, mailbox);

                var view = new CalendarView(range.Start, range.End)
                {
                    PropertySet = new PropertySet(BasePropertySet.IdOnly)
                };

                var results = calendar.FindAppointments(view);
                var loaded = LoadAppointments(
                    threadService, results, mailbox,
                    $"{mailbox} {range.Start:d}-{range.End:d}");

                chunkResults.Add(loaded.ToList());
            }
            catch (Exception ex)
            {
                _logger.Error(WithMailbox(mailbox,
                    $"Failed to read chunk {range.Start:d}-{range.End:d}: {ex.Message}"), ex);
            }
        });

        // Deduplicate collected appointments on the main thread
        var service = CreateService(ewsUri, exchangeTimeZone);
        var itemsToExport = new List<Appointment>();
        var uniqueIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var chunkAppointments in chunkResults)
        {
            foreach (var appointment in chunkAppointments)
            {
                if (appointment == null)
                {
                    continue;
                }

                var appointmentType = appointment.AppointmentType;

                if (appointmentType == AppointmentType.RecurringMaster &&
                    !string.IsNullOrWhiteSpace(appointment.ICalUid) &&
                    masterCache.Contains(appointment.ICalUid))
                {
                    continue;
                }

                if (appointmentType == AppointmentType.Occurrence ||
                    appointmentType == AppointmentType.Exception)
                {
                    TryAddRecurringMaster(service, appointment, itemsToExport, masterCache, mailbox);
                    continue;
                }

                var uniqueKey = appointment.Id?.UniqueId ?? appointment.ICalUid;
                if (!string.IsNullOrWhiteSpace(uniqueKey) && !uniqueIds.Add(uniqueKey))
                {
                    continue;
                }

                itemsToExport.Add(appointment);

                if (appointmentType == AppointmentType.RecurringMaster &&
                    !string.IsNullOrWhiteSpace(appointment.ICalUid))
                {
                    masterCache.Add(appointment.ICalUid);
                }
            }
        }

        WriteIcsFiles(mailbox, itemsToExport);
    }

    private CalendarFolder BindCalendarFolder(ExchangeService service, string mailbox)
    {
        var calendarId = new FolderId(WellKnownFolderName.Calendar, new Mailbox(mailbox));
        try
        {
            return CalendarFolder.Bind(service, calendarId);
        }
        catch (ServiceResponseException ex) when (ex.ErrorCode == ServiceError.ErrorFolderNotFound)
        {
            _logger.Warn(WithMailbox(mailbox, "Calendar folder not found. Retrying with impersonation."));
            service.ImpersonatedUserId = new ImpersonatedUserId(ConnectingIdType.SmtpAddress, mailbox);
            try
            {
                return CalendarFolder.Bind(service, WellKnownFolderName.Calendar);
            }
            catch
            {
                service.ImpersonatedUserId = null;
                throw;
            }
        }
    }

    private void TryAddRecurringMaster(
        ExchangeService service,
        Appointment appointment,
        List<Appointment> target,
        HashSet<string> masterCache,
        string mailbox)
    {
        if (appointment.AppointmentType == AppointmentType.RecurringMaster)
        {
            return;
        }

        if (appointment.AppointmentType != AppointmentType.Occurrence &&
            appointment.AppointmentType != AppointmentType.Exception)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(appointment.ICalUid) || masterCache.Contains(appointment.ICalUid))
        {
            return;
        }

        try
        {
            var master = Appointment.BindToRecurringMaster(service, appointment.Id);
            master.Load(_loadPropertySet);

            if (master.AppointmentType == AppointmentType.RecurringMaster)
            {
                target.Add(master);
                masterCache.Add(appointment.ICalUid);
                _logger.Debug(WithMailbox(mailbox, $"Added recurrence master for UID {appointment.ICalUid}"));
            }
        }
        catch (ServiceResponseException ex)
        {
            _logger.Warn(WithMailbox(mailbox, $"Could not load recurrence master for UID {appointment.ICalUid}: {ex.ErrorCode} - {ex.Message}"));
        }
        catch (ServiceRequestException ex)
        {
            _logger.Warn(WithMailbox(mailbox, $"Could not load recurrence master for UID {appointment.ICalUid}: request failed - {ex.Message}"));
        }
        catch (Exception ex)
        {
            _logger.Warn(WithMailbox(mailbox, $"Could not load recurrence master for UID {appointment.ICalUid}: unexpected error - {ex.Message}"));
        }
    }

    private void WriteIcsFiles(string mailbox, IEnumerable<Appointment> appointments)
    {
        var appointmentList = appointments.ToList();
        if (appointmentList.Count == 0)
        {
            _logger.Warn(WithMailbox(mailbox, "No appointments found for export."));
            return;
        }

        var writer = new IcsBatchWriter(mailbox, _config.OutputDirectory, _config.FileMaxSizeMb, _logger);
        var count = 0;

        foreach (var appointment in appointmentList)
        {
            if (appointment.MimeContent == null)
            {
                _logger.Warn(WithMailbox(mailbox, $"Skipping item without MIME content: {appointment.Id?.UniqueId}"));
                continue;
            }

            writer.AppendFromAppointment(appointment);
            count++;
        }

        writer.Complete();
        _logger.Info(WithMailbox(mailbox, $"Exported {count} appointments."));
    }
    private IReadOnlyList<Appointment> LoadAppointments(ExchangeService service, IEnumerable<Appointment> items, string mailbox, string context)
    {
        var list = items.ToList();
        if (list.Count == 0)
        {
            return list;
        }

        const int batchSize = 200;
        var loaded = new List<Appointment>(list.Count);

        for (var offset = 0; offset < list.Count; offset += batchSize)
        {
            var batch = list.Skip(offset).Take(batchSize).ToList();
            ServiceResponseCollection<ServiceResponse>? responses = null;

            try
            {
                responses = service.LoadPropertiesForItems(batch, _loadPropertySet);
            }
            catch (ServiceRequestException ex)
            {
                _logger.Warn(WithMailbox(mailbox, $"Batch load failed in {context} ({offset}-{offset + batch.Count - 1}): request failed - {ex.Message}"));
            }
            catch (Exception ex)
            {
                _logger.Warn(WithMailbox(mailbox, $"Batch load failed in {context} ({offset}-{offset + batch.Count - 1}): unexpected error - {ex.Message}"));
            }

            if (responses == null)
            {
                continue;
            }

            for (var i = 0; i < responses.Count; i++)
            {
                var response = responses[i];
                var item = batch[i];

                if (response.Result == ServiceResult.Success)
                {
                    loaded.Add(item);
                }
                else
                {
                    _logger.Warn(WithMailbox(mailbox, $"Skipping item {item.Id?.UniqueId} in {context}: {response.ErrorCode} - {response.ErrorMessage}"));
                }
            }
        }

        return loaded;
    }

    private static string WithMailbox(string mailbox, string message) => $"[{mailbox}] {message}";
}

internal sealed class IcsBatchWriter
{
    private readonly string _mailboxId;
    private readonly string _mailboxSafeName;
    private readonly string _outputDir;
    private readonly int _maxBytes;
    private readonly Logger _logger;

    private readonly StringBuilder _builder = new();
    private readonly HashSet<string> _timezones = new(StringComparer.OrdinalIgnoreCase);
    private int _fileCounter = 1;
    private int _eventCount;

    public IcsBatchWriter(string mailbox, string outputDir, int fileMaxSizeMb, Logger logger)
    {
        _mailboxId = mailbox;
        _mailboxSafeName = SanitizeFileName(mailbox);
        _outputDir = outputDir;
        _maxBytes = fileMaxSizeMb * 1024 * 1024;
        _logger = logger;
        StartNewFile();
    }

    public void AppendFromAppointment(Appointment appointment)
    {
        var charset = string.IsNullOrWhiteSpace(appointment.MimeContent.CharacterSet)
            ? Encoding.UTF8
            : Encoding.GetEncoding(appointment.MimeContent.CharacterSet);

        var raw = charset.GetString(appointment.MimeContent.Content);
        var blocks = IcsBlockExtractor.Extract(raw);

        foreach (var tz in blocks.Timezones)
        {
            AppendBlock(tz, isTimezone: true);
        }

        foreach (var evt in blocks.Events)
        {
            var withParticipants = IcsEventAugmenter.EnsureParticipants(evt, appointment, _logger, _mailboxId);
            AppendBlock(withParticipants, isTimezone: false);
        }
    }

    public void Complete()
    {
        Flush(forceWrite: false, startNew: false);
    }

    private void StartNewFile()
    {
        _builder.Clear();
        _timezones.Clear();
        _eventCount = 0;

        _builder.AppendLine("BEGIN:VCALENDAR");
        _builder.AppendLine("VERSION:2.0");
        _builder.AppendLine("PRODID:-//ExchangeCalendarMigrator//EN");
        _builder.AppendLine("METHOD:PUBLISH");
    }

    private void AppendBlock(string block, bool isTimezone)
    {
        block = IcsLineFolder.UnfoldAndFoldBlock(block);
        if (isTimezone && _timezones.Contains(block))
        {
            return;
        }

        var blockBytes = Encoding.UTF8.GetByteCount(block + "\r\n");
        var footerBytes = Encoding.UTF8.GetByteCount("END:VCALENDAR\r\n");

        var projectedBytes = CurrentBytes + blockBytes + footerBytes;
        if (projectedBytes > _maxBytes && (_eventCount > 0 || _timezones.Count > 0))
        {
            Flush(forceWrite: true, startNew: true);
            projectedBytes = CurrentBytes + blockBytes + footerBytes;
        }

        if (projectedBytes > _maxBytes)
        {
            _logger.Warn(WithMailboxPrefix($"Skipping {(isTimezone ? "timezone" : "event")} block for {_mailboxSafeName}: exceeds file_max_size limit."));
            return;
        }

        _builder.AppendLine(block);

        if (isTimezone)
        {
            _timezones.Add(block);
        }
        else
        {
            _eventCount++;
        }
    }

    private void Flush(bool forceWrite, bool startNew)
    {
        if (!forceWrite && _eventCount == 0 && _timezones.Count == 0)
        {
            return;
        }

        _builder.AppendLine("END:VCALENDAR");
        var path = Path.Combine(_outputDir, $"{_mailboxSafeName}_{_fileCounter}.ics");
        while (File.Exists(path))
        {
            _fileCounter++;
            path = Path.Combine(_outputDir, $"{_mailboxSafeName}_{_fileCounter}.ics");
        }
        File.WriteAllText(path, _builder.ToString(), Encoding.UTF8);
        _logger.Info(WithMailboxPrefix($"Created {path} with {_eventCount} events."));
        _fileCounter++;
        if (startNew)
        {
            StartNewFile();
        }
    }

    private int CurrentBytes => Encoding.UTF8.GetByteCount(_builder.ToString());

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "mailbox" : cleaned;
    }

    private string WithMailboxPrefix(string message) => $"[{_mailboxId}] {message}";
}

internal static class IcsEventAugmenter
{
    public static string EnsureParticipants(string eventBlock, Appointment appointment, Logger logger, string mailbox)
    {
        if (appointment == null || string.IsNullOrWhiteSpace(eventBlock))
        {
            return eventBlock;
        }

        var normalizedLines = eventBlock.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();
        var endIndex = normalizedLines.FindLastIndex(l => l.StartsWith("END:VEVENT", StringComparison.OrdinalIgnoreCase));
        if (endIndex < 0)
        {
            return eventBlock;
        }

        var hasOrganizer = ContainsLine(normalizedLines, "ORGANIZER");
        var hasAttendee = ContainsLine(normalizedLines, "ATTENDEE");

        var toInsert = new List<string>();

        if (!hasOrganizer)
        {
            var organizerLine = BuildOrganizerLine(appointment.Organizer);
            if (organizerLine != null)
            {
                toInsert.AddRange(IcsLineFolder.FoldLines(organizerLine));
            }
        }

        if (!hasAttendee)
        {
            toInsert.AddRange(BuildAttendees(appointment.RequiredAttendees, "REQ-PARTICIPANT"));
            toInsert.AddRange(BuildAttendees(appointment.OptionalAttendees, "OPT-PARTICIPANT"));
            toInsert.AddRange(BuildAttendees(appointment.Resources, "NON-PARTICIPANT"));
        }

        if (toInsert.Count == 0)
        {
            return eventBlock;
        }

        normalizedLines.InsertRange(endIndex, toInsert);
        logger.Debug($"[{mailbox}] Injected participant data into VEVENT {appointment.ICalUid ?? appointment.Id?.UniqueId}");
        return string.Join("\r\n", normalizedLines);
    }

    private static bool ContainsLine(IEnumerable<string> lines, string token)
    {
        return lines.Any(l => l.StartsWith(token, StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> BuildAttendees(IEnumerable<Attendee> attendees, string role)
    {
        var list = new List<string>();
        if (attendees == null)
        {
            return list;
        }

        foreach (var attendee in attendees)
        {
            if (string.IsNullOrWhiteSpace(attendee.Address))
            {
                continue;
            }

            var cnPart = string.IsNullOrWhiteSpace(attendee.Name) ? string.Empty : $";CN={Escape(attendee.Name)}";
            var partStat = MapResponse(attendee.ResponseType);
            var line = $"ATTENDEE;ROLE={role};PARTSTAT={partStat}{cnPart}:mailto:{Escape(attendee.Address)}";
            list.AddRange(IcsLineFolder.FoldLines(line));
        }

        return list;
    }

    private static string? BuildOrganizerLine(EmailAddress? organizer)
    {
        if (organizer == null || string.IsNullOrWhiteSpace(organizer.Address))
        {
            return null;
        }

        var cnPart = string.IsNullOrWhiteSpace(organizer.Name) ? string.Empty : $";CN={Escape(organizer.Name)}";
        return $"ORGANIZER{cnPart}:mailto:{Escape(organizer.Address)}";
    }

    private static string MapResponse(MeetingResponseType? responseType)
    {
        return responseType switch
        {
            MeetingResponseType.Accept => "ACCEPTED",
            MeetingResponseType.Tentative => "TENTATIVE",
            MeetingResponseType.Decline => "DECLINED",
            _ => "NEEDS-ACTION"
        };
    }

    private static string Escape(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace(";", "\\;", StringComparison.Ordinal)
            .Replace(",", "\\,", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal);
    }
}

internal static class IcsLineFolder
{
    private const int Limit = 75;

    public static string UnfoldAndFoldBlock(string block)
    {
        if (string.IsNullOrWhiteSpace(block))
        {
            return block;
        }

        var normalized = block.Replace("\r\n", "\n", StringComparison.Ordinal);
        var lines = normalized.Split('\n');
        var unfolded = new List<string>(lines.Length);

        foreach (var line in lines)
        {
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t') && unfolded.Count > 0)
            {
                unfolded[unfolded.Count - 1] += line.Substring(1);
            }
            else
            {
                unfolded.Add(line);
            }
        }

        var folded = new List<string>(unfolded.Count * 2);
        foreach (var line in unfolded)
        {
            if (line.Length == 0)
            {
                folded.Add(line);
                continue;
            }

            folded.AddRange(FoldLines(line));
        }

        return string.Join("\r\n", folded);
    }

    public static IEnumerable<string> FoldLines(string line)
    {
        if (line.Length <= Limit)
        {
            yield return line;
            yield break;
        }

        var emailSpans = FindEmailSpans(line);
        var index = 0;
        var firstLine = true;

        while (index < line.Length)
        {
            var availableLength = firstLine ? Limit : Limit - 1; // Reserve space for leading space on continuation lines
            var remaining = line.Length - index;

            if (remaining <= availableLength)
            {
                var lastSegment = line.Substring(index);
                if (!firstLine)
                {
                    lastSegment = " " + lastSegment;
                }
                yield return lastSegment;
                break;
            }

            var breakPoint = FindBreakPoint(line, index, availableLength, emailSpans);
            var segment = line.Substring(index, breakPoint);
            if (!firstLine)
            {
                segment = " " + segment;
            }

            yield return segment;
            index += breakPoint;

            while (index < line.Length && line[index] == ' ')
            {
                index++;
            }

            firstLine = false;
        }
    }

    private static int FindBreakPoint(
        string line,
        int startIndex,
        int maxLength,
        IReadOnlyList<(int Start, int End)> emailSpans)
    {
        var endIndex = startIndex + maxLength;
        if (endIndex >= line.Length)
        {
            return line.Length - startIndex;
        }

        foreach (var span in emailSpans)
        {
            if (endIndex > span.Start && endIndex < span.End)
            {
                if (span.Start > startIndex)
                {
                    return span.Start - startIndex;
                }

                return span.End - startIndex;
            }
        }

        var searchStart = Math.Max(0, maxLength - 20);
        for (var i = Math.Min(maxLength - 1, line.Length - startIndex - 1); i >= searchStart; i--)
        {
            var absolutePos = startIndex + i;
            if (absolutePos >= line.Length)
            {
                continue;
            }

            var ch = line[absolutePos];
            if (ch == ' ')
            {
                return i;
            }

            if (ch == ',' || ch == ';')
            {
                return i + 1;
            }
        }

        return Math.Min(maxLength, line.Length - startIndex);
    }

    private static IReadOnlyList<(int Start, int End)> FindEmailSpans(string line)
    {
        var spans = new List<(int Start, int End)>();

        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] != '@')
            {
                continue;
            }

            var start = i - 1;
            while (start >= 0 && !IsEmailDelimiter(line[start]))
            {
                start--;
            }
            start++;

            var end = i + 1;
            while (end < line.Length && !IsEmailDelimiter(line[end]))
            {
                end++;
            }

            if (start < i && end > i + 1)
            {
                spans.Add((start, end));
            }
        }

        return spans;
    }

    private static bool IsEmailDelimiter(char ch)
    {
        return char.IsWhiteSpace(ch) ||
               ch == ';' ||
               ch == ',' ||
               ch == ':' ||
               ch == '<' ||
               ch == '>' ||
               ch == '"';
    }
}

internal static class IcsBlockExtractor
{
    public static (IReadOnlyList<string> Timezones, IReadOnlyList<string> Events) Extract(string icsContent)
    {
        var normalized = icsContent.Replace("\r\n", "\n", StringComparison.Ordinal);
        var lines = normalized.Split('\n');

        var tzBlocks = new List<string>();
        var eventBlocks = new List<string>();

        List<string>? buffer = null;
        string? currentType = null;

        foreach (var line in lines)
        {
            if (buffer == null && line.StartsWith("BEGIN:", StringComparison.OrdinalIgnoreCase))
            {
                var blockType = line["BEGIN:".Length..].Trim();
                if (blockType.Equals("VEVENT", StringComparison.OrdinalIgnoreCase) ||
                    blockType.Equals("VTIMEZONE", StringComparison.OrdinalIgnoreCase))
                {
                    currentType = blockType;
                    buffer = new List<string> { line };
                    continue;
                }
            }

            if (buffer == null)
            {
                continue;
            }

            buffer.Add(line);

            if (line.StartsWith("END:", StringComparison.OrdinalIgnoreCase) && currentType != null)
            {
                var blockType = line["END:".Length..].Trim();
                if (blockType.Equals(currentType, StringComparison.OrdinalIgnoreCase))
                {
                    var blockText = string.Join("\r\n", buffer);
                    if (currentType.Equals("VEVENT", StringComparison.OrdinalIgnoreCase))
                    {
                        eventBlocks.Add(blockText);
                    }
                    else
                    {
                        tzBlocks.Add(blockText);
                    }

                    buffer = null;
                    currentType = null;
                }
            }
        }

        return (tzBlocks, eventBlocks);
    }
}

internal sealed class Logger : IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private readonly AsyncLocal<string?> _mailboxPrefix = new();

    public Logger(string logPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? ".");
        _writer = new StreamWriter(File.Open(logPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };
    }

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Debug(string message) => Write("DEBUG", message);

    public void Error(string message, Exception? ex = null)
    {
        var details = ex == null ? message : $"{message}. Exception: {ex}";
        Write("ERROR", details);
    }

    private void Write(string level, string message)
    {
        var line = $"{DateTime.UtcNow:o} [{level}] {Format(message)}";
        lock (_gate)
        {
            Console.WriteLine(line);
            _writer.WriteLine(line);
        }
    }

    public IDisposable BeginMailboxScope(string mailbox)
    {
        var previous = _mailboxPrefix.Value;
        _mailboxPrefix.Value = $"[{mailbox}] ";
        return new MailboxScope(this, previous);
    }

    private string Format(string message)
    {
        var prefix = _mailboxPrefix.Value;
        if (string.IsNullOrEmpty(prefix) || message.StartsWith(prefix, StringComparison.Ordinal))
        {
            return message;
        }

        return prefix + message;
    }

    public void Dispose()
    {
        _writer.Dispose();
    }

    private sealed class MailboxScope : IDisposable
    {
        private readonly Logger _logger;
        private readonly string? _previous;

        public MailboxScope(Logger logger, string? previous)
        {
            _logger = logger;
            _previous = previous;
        }

        public void Dispose()
        {
            _logger._mailboxPrefix.Value = _previous;
        }
    }
}


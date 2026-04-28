
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'package:percent_indicator/percent_indicator.dart';

void main() {
  runApp(const SecureAPKApp());
}


const String apiAnalyzeUrl = "https://secureapk.online/analyze";
const String apiHealthUrl = "https://secureapk.online/health";

class SecureAPKApp extends StatelessWidget {
  const SecureAPKApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureAPK',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        useMaterial3: true,
        fontFamily: 'Inter',
        scaffoldBackgroundColor: const Color(0xFF041021),
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF7C3AED),
          brightness: Brightness.dark,
        ).copyWith(
          primary: const Color(0xFF7C3AED),
          secondary: const Color(0xFF0EA5A4),
          surface: const Color(0xFF071427),
        ),
        textTheme: const TextTheme(
          bodyMedium: TextStyle(color: Colors.white),
          bodyLarge: TextStyle(color: Colors.white),
          titleMedium: TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
          titleLarge: TextStyle(color: Colors.white, fontWeight: FontWeight.w700),
        ),
      ),
      home: const SplashScreen(),
    );
  }
}

class AnalysisResult {
  final Map<String, dynamic>? meta;
  final Map<String, dynamic>? analysis;
  final Map<String, dynamic>? model;

  AnalysisResult({this.meta, this.analysis, this.model});

  factory AnalysisResult.fromJson(Map<String, dynamic> json) {
    return AnalysisResult(
      meta: json['meta'] != null ? Map<String, dynamic>.from(json['meta']) : null,
      analysis: json['analysis'] != null ? Map<String, dynamic>.from(json['analysis']) : null,
      model: json['model'] != null ? Map<String, dynamic>.from(json['model']) : null,
    );
  }
}

class _SessionEntry {
  final String name;
  final String time;
  final String sha256;
  final AnalysisResult result;

  _SessionEntry({
    required this.name,
    required this.time,
    required this.sha256,
    required this.result,
  });
}

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _fade;
  late final Animation<double> _scale;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1100),
    )..forward();

    _fade = CurvedAnimation(parent: _controller, curve: Curves.easeOut);
    _scale = Tween<double>(begin: 0.94, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic),
    );

    Future.delayed(const Duration(milliseconds: 1800), () {
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        PageRouteBuilder(
          transitionDuration: const Duration(milliseconds: 650),
          pageBuilder: (_, animation, __) => FadeTransition(
            opacity: animation,
            child: const HomePage(),
          ),
        ),
      );
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF020712), Color(0xFF071024), Color(0xFF071C2A)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        child: Center(
          child: FadeTransition(
            opacity: _fade,
            child: ScaleTransition(
              scale: _scale,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 98,
                    height: 98,
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(28),
                      gradient: const LinearGradient(
                        colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFF7C3AED).withOpacity(0.30),
                          blurRadius: 40,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(28),
                      child: Image.asset(
                        "assets/logo.png",
                        fit: BoxFit.cover,
                      ),
                    ),
                  ),
                  const SizedBox(height: 20),
                  const Text(
                    'SecureAPK',
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.2,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Next-Gen Mobile Threat Analysis Tool',
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.70),
                      fontSize: 13,
                    ),
                  ),
                  const SizedBox(height: 28),
                  SizedBox(
                    width: 220,
                    child: LinearProgressIndicator(
                      minHeight: 6,
                      borderRadius: BorderRadius.circular(999),
                      backgroundColor: Colors.white.withOpacity(0.08),
                      valueColor: const AlwaysStoppedAnimation(Color(0xFF0EA5A4)),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

enum TabItem { overview, staticTab, ml, intel, yara }

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  TabItem _current = TabItem.overview;
  AnalysisResult? _result;
  bool _isUploading = false;
  double _uploadProgress = 0.0;
  String? _currentFileName;
  String _apiStatus = "checking";
  Timer? _progressTimer;
  final TextEditingController _yaraController = TextEditingController();
  final List<_SessionEntry> _sessions = [];

  @override
  void initState() {
    super.initState();
    _checkApiHealth();
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    _yaraController.dispose();
    super.dispose();
  }

  Future<void> _checkApiHealth() async {
    try {
      final resp = await http.get(Uri.parse(apiHealthUrl)).timeout(const Duration(seconds: 3));
      if (!mounted) return;
      if (resp.statusCode == 200) {
        final j = jsonDecode(resp.body);
        setState(() => _apiStatus = j['status']?.toString() ?? 'ok');
      } else {
        setState(() => _apiStatus = 'down');
      }
    } catch (_) {
      if (mounted) {
        setState(() => _apiStatus = 'down');
      }
    }
  }

  Future<void> _pickAndUploadApk() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['apk'],
        withReadStream: true,
      );

      if (result == null) return;

      final fileBytes = result.files.single.bytes;
      final path = result.files.single.path;
      final name = result.files.single.name;
      setState(() => _currentFileName = name);

      if (path == null && fileBytes == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Failed to pick file path.')),
        );
        return;
      }

      late final File file;
      if (path != null) {
        file = File(path);
      } else {
        final tmp = await getTemporaryDirectory();
        final tmpFile = File('${tmp.path}/$name');
        await tmpFile.writeAsBytes(fileBytes!);
        file = tmpFile;
      }

      await _uploadFile(file);
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error picking file: $e')),
      );
    }
  }

  Future<void> _uploadFile(File file) async {
    setState(() {
      _isUploading = true;
      _uploadProgress = 0.02;
    });
    _startPseudoProgress();

    try {
      final uri = Uri.parse(apiAnalyzeUrl);
      final request = http.MultipartRequest('POST', uri);
      final fileLength = await file.length();
      final stream = http.ByteStream(file.openRead());
      final multipartFile = http.MultipartFile(
        'file',
        stream,
        fileLength,
        filename: file.path.split('/').last,
      );
      request.files.add(multipartFile);

      final streamedResponse = await request.send().timeout(const Duration(seconds: 120));
      final respStr = await streamedResponse.stream.bytesToString();

      if (streamedResponse.statusCode == 200) {
        final Map<String, dynamic> j = jsonDecode(respStr);
        final newResult = AnalysisResult.fromJson(j);
        final yaraText = _generateYaraText(newResult, fallbackIfMissing: true);

        if (!mounted) return;
        setState(() {
          _result = newResult;
          _yaraController.text = yaraText;
          _current = TabItem.overview;
          _sessions.insert(
            0,
            _SessionEntry(
              name: file.path.split('/').last,
              time: DateTime.now().toIso8601String(),
              sha256: newResult.meta?['sha256'] ?? '—',
              result: newResult,
            ),
          );
        });

        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Analysis complete')),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Upload failed: ${streamedResponse.statusCode}')),
        );
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error uploading file: $e')),
      );
    } finally {
      _stopPseudoProgress();
      if (!mounted) return;
      setState(() {
        _isUploading = false;
        _uploadProgress = 1.0;
      });
      Future.delayed(const Duration(milliseconds: 650), () {
        if (mounted) {
          setState(() => _uploadProgress = 0.0);
        }
      });
      _checkApiHealth();
    }
  }

  void _startPseudoProgress() {
    _progressTimer?.cancel();
    _progressTimer = Timer.periodic(const Duration(milliseconds: 220), (t) {
      if (!mounted) return;
      setState(() {
        if (_uploadProgress < 0.9) {
          _uploadProgress += 0.02 + (0.02 * (t.tick % 4));
        }
        if (_uploadProgress > 0.9) _uploadProgress = 0.9;
      });
    });
  }

  void _stopPseudoProgress() {
    _progressTimer?.cancel();
    _progressTimer = null;
    if (mounted) {
      setState(() => _uploadProgress = 0.95);
    }
  }

  String _generateYaraText(AnalysisResult? r, {bool fallbackIfMissing = false}) {
    if (r == null) return '';
    final analysis = r.analysis ?? {};
    if (analysis.containsKey('yara') &&
        analysis['yara'] is String &&
        (analysis['yara'] as String).isNotEmpty) {
      return analysis['yara'];
    }

    final appLabel = r.meta?['app_label'] ?? r.meta?['package'] ?? 'unknown_app';
    final suspicious = analysis['suspicious'] ?? {};
    final List<dynamic> strings =
    (suspicious['strings'] is List) ? List<dynamic>.from(suspicious['strings']) : [];
    final List<String> tokens = [];
    for (final s in strings.take(12)) {
      final ss = s.toString().trim();
      if (ss.length > 3) tokens.add(ss.replaceAll('"', ''));
    }

    final ruleName = 'SecureAPK_${appLabel.toString().replaceAll(RegExp(r'[^a-zA-Z0-9_]'), '_')}';
    final buffer = StringBuffer()
      ..writeln('rule $ruleName {')
      ..writeln('  meta:')
      ..writeln('    description = "Auto-generated YARA from SecureAPK mobile analysis"')
      ..writeln('    source = "SecureAPK-flutter-client"')
      ..writeln('  strings:');

    if (tokens.isEmpty) {
      buffer.writeln('    \$s0 = "SecureAPK_placeholder"');
    } else {
      for (var i = 0; i < tokens.length; i++) {
        buffer.writeln('    \$s$i = "${tokens[i]}" nocase');
      }
    }

    buffer.writeln('  condition:');
    buffer.writeln(tokens.isEmpty ? '    false' : '    any of them');
    buffer.writeln('}');
    return buffer.toString();
  }

  Future<void> _copyYaraToClipboard() async {
    final text = _yaraController.text;
    if (text.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('YARA copied to clipboard')),
    );
  }

  Future<void> _saveYaraToFile() async {
    final text = _yaraController.text;
    if (text.isEmpty) return;
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/SecureAPK_rule_${DateTime.now().millisecondsSinceEpoch}.yar');
      await file.writeAsString(text);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Saved to ${file.path}')),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed saving: $e')),
      );
    }
  }

  void _openSession(_SessionEntry session) {
    setState(() {
      _result = session.result;
      _currentFileName = session.name;
      _yaraController.text = _generateYaraText(session.result, fallbackIfMissing: true);
      _current = TabItem.overview;
    });
  }

  Widget _buildScaffoldBody() {
    switch (_current) {
      case TabItem.overview:
        return _OverviewTab(
          result: _result,
          onGotoMl: () => setState(() => _current = TabItem.ml),
          onGotoStatic: () => setState(() => _current = TabItem.staticTab),
          onUpload: _pickAndUploadApk,
        );
      case TabItem.staticTab:
        return _StaticTab(result: _result);
      case TabItem.ml:
        return _MlTab(result: _result);
      case TabItem.intel:
        return _IntelTab(result: _result);
      case TabItem.yara:
        return _YaraTab(
          yaraController: _yaraController,
          onCopy: _copyYaraToClipboard,
          onSave: _saveYaraToFile,
        );
    }
  }

  Widget _navItem(IconData icon, String label, TabItem item, {bool rail = false}) {
    final active = _current == item;
    final color = active ? const Color(0xFF000001) : Colors.white70;
    final bg = active
        ? Colors.white.withOpacity(0.25)  // was 0.05
        : Colors.white.withOpacity(0.10); // was transparent

    return InkWell(
      onTap: () => setState(() => _current = item),
      borderRadius: BorderRadius.circular(16),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOut,
        width: rail ? double.infinity : null,
        padding: EdgeInsets.symmetric(
          horizontal: rail ? 14 : 10,
          vertical: rail ? 14 : 10,
        ),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: active ? const Color(0xFF7C3AED).withOpacity(0.22) : Colors.white.withOpacity(0.10),
          ),
        ),
        child: Row(
          mainAxisAlignment: rail ? MainAxisAlignment.start : MainAxisAlignment.center,
          children: [
            Icon(icon, size: 20, color: color),
            if (rail) ...[
              const SizedBox(width: 12),
              Text(label, style: TextStyle(color: color, fontWeight: FontWeight.w600)),
            ] else ...[
              const SizedBox(height: 0),
              if (!rail) ...[
                const SizedBox(height: 2),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget _statusChip() {
    final ok = _apiStatus == 'ok';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: (ok ? Colors.green : Colors.red).withOpacity(0.10),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: (ok ? Colors.green : Colors.red).withOpacity(0.22)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: ok ? Colors.green : Colors.red,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            'API: $_apiStatus',
            style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
          ),
        ],
      ),
    );
  }

  Widget _heroCard(bool compact) {
    return Container(
      padding: EdgeInsets.all(compact ? 16 : 22),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(28),
        gradient: LinearGradient(
          colors: [
            Colors.white.withOpacity(0.06),
            Colors.white.withOpacity(0.025),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.25),
            blurRadius: 30,
            offset: const Offset(0, 18),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            width: compact ? 54 : 64,
            height: compact ? 54 : 64,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(18),
              gradient: const LinearGradient(
                colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            child: const Icon(Icons.shield, color: Colors.white, size: 30),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'SecureAPK Analysis Console',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 6),
                Text(
                  'SecureAPK combines static analysis, ML detection, and threat intelligence for serious security teams.',
                  style: TextStyle(color: Colors.white.withOpacity(0.70), height: 1.3),
                ),
              ],
            ),
          ),
          if (!compact)
            FilledButton.icon(
              onPressed: _isUploading ? null : _pickAndUploadApk,
              icon: const Icon(Icons.upload_file),
              label: Text(_isUploading ? 'Analyzing…' : 'Upload APK'),
              style: FilledButton.styleFrom(
                backgroundColor: const Color(0xFF0EA5A4),
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
              ),
            ),
        ],
      ),
    );
  }

  Widget _recentSessionsCard() {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        color: Colors.white.withOpacity(0.03),
        border: Border.all(color: Colors.white.withOpacity(0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.history, size: 18, color: Colors.white70),
              SizedBox(width: 8),
              Text('Recent analyses', style: TextStyle(fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 14),
          if (_sessions.isEmpty)
            Text(
              'No analysis yet. Upload an APK to see the latest run here.',
              style: TextStyle(color: Colors.white.withOpacity(0.55)),
            )
          else
            ..._sessions.take(4).map(
                  (s) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: InkWell(
                  borderRadius: BorderRadius.circular(16),
                  onTap: () => _openSession(s),
                  child: Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: Colors.white.withOpacity(0.03),
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: Row(
                      children: [
                        Container(
                          width: 38,
                          height: 38,
                          decoration: BoxDecoration(
                            color: const Color(0xFF0EA5A4).withOpacity(0.12),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: const Icon(Icons.file_present, size: 18, color: Color(0xFF0EA5A4)),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(s.name, maxLines: 1, overflow: TextOverflow.ellipsis),
                              const SizedBox(height: 3),
                              Text(
                                s.sha256 == '—' ? s.time : s.sha256,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: TextStyle(color: Colors.white.withOpacity(0.50), fontSize: 12),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _mobileShell(BoxConstraints constraints) {
    return Stack(
      children: [
        SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 120),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _heroCard(true),
              const SizedBox(height: 16),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  _statusChip(),
                  if (_currentFileName != null)
                    _smallChip(Icons.insert_drive_file, _currentFileName!),
                ],
              ),
              const SizedBox(height: 16),
              LayoutBuilder(
                builder: (context, inner) {
                  final compact = inner.maxWidth < 700;
                  return _buildSectionBody(compact);
                },
              ),
              const SizedBox(height: 16),
              _recentSessionsCard(),
            ],
          ),
        ),
        Positioned(
          left: 14,
          right: 14,
          bottom: 14,
          child: Container(
            height: 70,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            decoration: BoxDecoration(
              color: Colors.black38.withOpacity(0.90),
              borderRadius: BorderRadius.circular(22),
              border: Border.all(color: Colors.white.withOpacity(0.06)),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.40),
                  blurRadius: 20,
                  offset: const Offset(0, 10),
                )
              ],
            ),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceAround,
              children: [
                _navItem(Icons.dashboard_rounded, 'Overview', TabItem.overview),
                _navItem(Icons.rule_folder_rounded, 'Static', TabItem.staticTab),
                _navItem(Icons.analytics_rounded, 'ML', TabItem.ml),
                _navItem(Icons.travel_explore_rounded, 'Intel', TabItem.intel),
              ],
            ),
          ),
        ),
        if (_isUploading)
          _uploadOverlay(),
      ],
    );
  }

  Widget _desktopShell(BoxConstraints constraints) {
    final railWidth = 280.0;
    return Stack(
      children: [
        Row(
          children: [
            Container(
              width: railWidth,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    Colors.white.withOpacity(0.03),
                    Colors.white.withOpacity(0.018),
                  ],
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                ),
                border: Border(
                  right: BorderSide(color: Colors.white.withOpacity(0.05)),
                ),
              ),
              child: SafeArea(
                child: Padding(
                  padding: const EdgeInsets.all(18),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Container(
                            width: 46,
                            height: 46,
                            decoration: BoxDecoration(
                              borderRadius: BorderRadius.circular(16),
                              gradient: const LinearGradient(
                                colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)],
                              ),
                            ),
                            child: ClipRRect(
                              borderRadius: BorderRadius.circular(16),
                              child: Image.asset("assets/logo.png", fit: BoxFit.cover),
                            ),
                          ),
                          const SizedBox(width: 12),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text('SecureAPK', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800)),
                                SizedBox(height: 2),
                                Text('AI-powered APK analysis', style: TextStyle(fontSize: 12, color: Colors.white60)),
                              ],
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 18),
                      _statusChip(),
                      const SizedBox(height: 18),
                      _navItem(Icons.dashboard_rounded, 'Overview', TabItem.overview, rail: true),
                      const SizedBox(height: 8),
                      _navItem(Icons.rule_folder_rounded, 'Static', TabItem.staticTab, rail: true),
                      const SizedBox(height: 8),
                      _navItem(Icons.analytics_rounded, 'ML', TabItem.ml, rail: true),
                      const SizedBox(height: 8),
                      _navItem(Icons.travel_explore_rounded, 'Intel', TabItem.intel, rail: true),
                      const SizedBox(height: 8),
                      _navItem(Icons.code_rounded, 'YARA', TabItem.yara, rail: true),
                      const Spacer(),
                      _smallSummaryCard(),
                    ],
                  ),
                ),
              ),
            ),
            Expanded(
              child: SafeArea(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.fromLTRB(24, 22, 24, 120),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _heroCard(false),
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 10,
                        runSpacing: 10,
                        children: [
                          _statusChip(),
                          if (_currentFileName != null)
                            _smallChip(Icons.insert_drive_file, _currentFileName!),
                        ],
                      ),
                      const SizedBox(height: 18),
                      LayoutBuilder(
                        builder: (context, inner) {
                          final compact = inner.maxWidth < 900;
                          return _buildSectionBody(compact);
                        },
                      ),
                      const SizedBox(height: 18),
                      _recentSessionsCard(),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
        if (_isUploading) _uploadOverlay(),
      ],
    );
  }

  Widget _buildSectionBody(bool compact) {
    return AnimatedSwitcher(
      duration: const Duration(milliseconds: 320),
      switchInCurve: Curves.easeOutCubic,
      switchOutCurve: Curves.easeInCubic,
      child: _buildScaffoldBody(),
    );
  }

  Widget _smallChip(IconData icon, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.04),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: Colors.white70),
          const SizedBox(width: 8),
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 240),
            child: Text(
              label,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 12),
            ),
          ),
        ],
      ),
    );
  }

  Widget _smallSummaryCard() {
    final score = _finalScore;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        color: Colors.white.withOpacity(0.04),
        border: Border.all(color: Colors.white.withOpacity(0.06)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Live summary', style: TextStyle(fontSize: 12, color: Colors.white60)),
          const SizedBox(height: 10),
          Text(
            '${(score * 100).toStringAsFixed(0)}% risk',
            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 4),
          Text(
            _decision,
            style: TextStyle(color: Colors.white.withOpacity(0.65), fontSize: 12),
          ),
        ],
      ),
    );
  }

  Widget _uploadOverlay() {
    return Positioned.fill(
      child: Container(
        color: Colors.black.withOpacity(0.55),
        child: Center(
          child: Container(
            width: 380,
            margin: const EdgeInsets.all(24),
            padding: const EdgeInsets.all(22),
            decoration: BoxDecoration(
              color: const Color(0xFF071427).withOpacity(0.94),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: Colors.white.withOpacity(0.06)),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.55),
                  blurRadius: 30,
                  offset: const Offset(0, 18),
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Row(
                  children: [
                    SizedBox(width: 4),
                    Icon(Icons.auto_awesome_rounded, color: Color(0xFF0EA5A4)),
                    SizedBox(width: 10),
                    Text('Uploading & Analyzing…', style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                  ],
                ),
                const SizedBox(height: 18),
                LinearPercentIndicator(
                  lineHeight: 12,
                  percent: _uploadProgress.clamp(0.0, 1.0),
                  linearStrokeCap: LinearStrokeCap.roundAll,
                  backgroundColor: Colors.white.withOpacity(0.08),
                  progressColor: const Color(0xFF7C3AED),
                  barRadius: const Radius.circular(999),
                  padding: EdgeInsets.zero,
                ),
                const SizedBox(height: 12),
                Text(
                  '${(_uploadProgress * 100).clamp(0, 100).toStringAsFixed(0)}%',
                  style: const TextStyle(fontSize: 14, color: Colors.white70),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  String get _decision {
    final d = _result?.model?['decision']?.toString();
    if (d != null && d.trim().isNotEmpty) return d;
    return '—';
  }

  double get _finalScore {
    final model = _result?.model;
    if (model == null) return 0.0;
    for (final key in ['final_score', 'risk_score', 'score']) {
      final v = model[key];
      if (v is num) return (v.toDouble() / 100.0).clamp(0.0, 1.0);
      if (v is String) {
        final parsed = double.tryParse(v);
        if (parsed != null) return (parsed / 100.0).clamp(0.0, 1.0);
      }
    }
    return 0.0;
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final wide = constraints.maxWidth >= 1100;
        final mobile = constraints.maxWidth < 900;

        return Scaffold(
          backgroundColor: Colors.transparent,
          appBar: mobile
              ? AppBar(
            backgroundColor: Colors.transparent,
            elevation: 0,
            titleSpacing: 0,
            title: Row(
              children: [
                Container(
                  width: 38,
                  height: 38,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    gradient: const LinearGradient(
                      colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)],
                    ),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(12),
                    child: Image.asset('assets/logo.png', fit: BoxFit.cover),
                  ),
                ),
                const SizedBox(width: 10),
                const Expanded(
                  child: Text('SecureAPK', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
                ),
              ],
            ),
            actions: [
              Padding(padding: const EdgeInsets.only(right: 12), child: _statusChip()),
            ],
          )
              : null,
          body: Container(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFF041021), Color(0xFF071024), Color(0xFF071C2A)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            child: wide ? _desktopShell(constraints) : _mobileShell(constraints),
          ),
        );
      },
    );
  }
}

class _OverviewTab extends StatelessWidget {
  final AnalysisResult? result;
  final VoidCallback onGotoMl;
  final VoidCallback onGotoStatic;
  final VoidCallback onUpload;

  const _OverviewTab({
    required this.result,
    required this.onGotoMl,
    required this.onGotoStatic,
    required this.onUpload,
  });

  double get finalScore {
    final model = result?.model;
    if (model == null) return 0.0;
    for (final key in ['final_score', 'risk_score', 'score']) {
      final v = model[key];
      if (v is num) return (v.toDouble() / 100.0).clamp(0.0, 1.0);
      if (v is String) {
        final parsed = double.tryParse(v);
        if (parsed != null) return (parsed / 100.0).clamp(0.0, 1.0);
      }
    }
    return 0.0;
  }

  double get mlProb {
    final v = result?.model?['probability_fake'];
    if (v is num) return (v.toDouble() / 100.0).clamp(0.0, 1.0);
    if (v is String) {
      final p = double.tryParse(v);
      if (p != null) return (p / 100.0).clamp(0.0, 1.0);
    }
    return 0.0;
  }

  String get decision => result?.model?['decision']?.toString() ?? '—';

  int _intFrom(Map? map, List<String> keys) {
    if (map == null) return 0;
    for (final k in keys) {
      final v = map[k];
      if (v is num) return v.toInt();
      if (v is String) return int.tryParse(v) ?? 0;
    }
    return 0;
  }

  int get vtDetections {
    final vt = result?.analysis?['vt'];
    if (vt is Map) {
      return _intFrom(vt, ['detections', 'positives', 'malicious', 'detected']);
    }
    return 0;
  }

  int get vtTotal {
    final vt = result?.analysis?['vt'];
    if (vt is Map) {
      return _intFrom(vt, ['total', 'total_scans', 'scan_count', 'total_engines']);
    }
    return 0;
  }

  int get ipCount {
    final s = result?.analysis?['suspicious'];
    if (s is Map) return _intFrom(s, ['ip_count', 'ips']);
    return 0;
  }

  int get urlCount {
    final s = result?.analysis?['suspicious'];
    if (s is Map) return _intFrom(s, ['url_count', 'urls']);
    return 0;
  }

  String get entropy {
    final s = result?.analysis?['suspicious'];
    if (s is Map && s['entropy'] != null) return s['entropy'].toString();
    return 'N/A';
  }

  int get suspiciousStringsCount {
    final s = result?.analysis?['suspicious'];
    if (s is Map && s['strings'] is List) return (s['strings'] as List).length;
    return 0;
  }

  @override
  Widget build(BuildContext context) {
    final score = finalScore;
    final riskLabel = score >= 0.75 ? 'High risk' : score >= 0.40 ? 'Elevated risk' : 'Low risk';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _TabHeader(
          title: 'Analysis overview',
          subtitle: 'A polished summary of the current APK verdict and signal breakdown.',
        ),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) {
            final narrow = constraints.maxWidth < 900;
            final overviewPane = Container(
              padding: const EdgeInsets.all(18),
              decoration: _cardDecoration(),
              child: Column(
                children: [
                  Wrap(
                    crossAxisAlignment: WrapCrossAlignment.center,
                    alignment: WrapAlignment.center,
                    spacing: 24,
                    runSpacing: 24,
                    children: [
                      CircularPercentIndicator(
                        radius: 82,
                        lineWidth: 12,
                        percent: score,
                        circularStrokeCap: CircularStrokeCap.round,
                        center: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              '${(score * 100).toStringAsFixed(0)}%',
                              style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w800),
                            ),
                            Text(
                              'Risk',
                              style: TextStyle(color: Colors.white.withOpacity(0.60), fontSize: 12),
                            ),
                          ],
                        ),
                        progressColor: score >= 0.75
                            ? Colors.redAccent
                            : score >= 0.40
                            ? Colors.orangeAccent
                            : Colors.greenAccent,
                        backgroundColor: Colors.white.withOpacity(0.06),
                      ),
                      ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 420),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            _sectionLabel('Verdict'),
                            const SizedBox(height: 8),
                            Text(
                              decision,
                              style: const TextStyle(fontSize: 26, fontWeight: FontWeight.w800),
                            ),
                            const SizedBox(height: 10),
                            Text(
                              riskLabel,
                              style: TextStyle(color: Colors.white.withOpacity(0.70), height: 1.35),
                            ),
                            const SizedBox(height: 16),
                            Wrap(
                              spacing: 10,
                              runSpacing: 10,
                              children: [
                                OutlinedButton(
                                  onPressed: onGotoMl,
                                  child: const Text('View ML'),
                                ),
                                OutlinedButton(
                                  onPressed: onGotoStatic,
                                  child: const Text('View Static'),
                                ),
                                FilledButton(
                                  onPressed: onUpload,
                                  child: const Text('Upload new APK'),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 18),
                  Row(
                    children: [
                      Expanded(child: _statCard('Final risk', '${(score * 100).toStringAsFixed(0)}%')),
                      const SizedBox(width: 10),
                      Expanded(child: _statCard('VirusTotal', '$vtDetections / ${vtTotal == 0 ? "—" : vtTotal}')),
                      const SizedBox(width: 10),
                      Expanded(child: _statCard('MalwareBazaar', result?.analysis?['malwarebazaar']?['detections']?.toString() ?? '—')),
                    ],
                  ),
                ],
              ),
            );

            return narrow
                ? Column(
              children: [
                overviewPane,
                const SizedBox(height: 14),
                _chartGrid(narrow: true),
              ],
            )
                : Column(
              children: [
                overviewPane,
                const SizedBox(height: 14),
                _chartGrid(narrow: false),
              ],
            );
          },
        ),
      ],
    );
  }
  Widget _chartGrid({required bool narrow}) {
    final charts = [
      _glassChartCard(
        title: 'VirusTotal',
        subtitle: vtTotal == 0 ? 'No detection summary available' : 'Detections: $vtDetections / $vtTotal',
        child: SizedBox(height: 160, child: _VTBarChart(detections: vtDetections.toDouble(), total: vtTotal.toDouble())),
      ),
      _glassChartCard(
        title: 'IOCs',
        subtitle: 'IPs: $ipCount • URLs: $urlCount • Strings: $suspiciousStringsCount',
        child: SizedBox(height: 160, child: _IocBarChart(ipCount: ipCount.toDouble(), urlCount: urlCount.toDouble(), stringsCount: suspiciousStringsCount.toDouble())),
      ),
    ];

    return narrow
        ? Column(children: [charts[0], const SizedBox(height: 12), charts[1]])
        : Row(children: [Expanded(child: charts[0]), const SizedBox(width: 12), Expanded(child: charts[1])]);
  }

  Widget _glassChartCard({
    required String title,
    required String subtitle,
    required Widget child,
  }) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionLabel(title),
          const SizedBox(height: 8),
          Text(subtitle, style: TextStyle(color: Colors.white.withOpacity(0.60), fontSize: 12)),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }

  Widget _statCard(String title, String value) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.03),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Colors.white.withOpacity(0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.55))),
          const SizedBox(height: 6),
          Text(value, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
        ],
      ),
    );
  }
}

class _StaticTab extends StatefulWidget {
  final AnalysisResult? result;
  const _StaticTab({required this.result});

  @override
  State<_StaticTab> createState() => _StaticTabState();
}

class _StaticTabState extends State<_StaticTab> {
  bool showDanger = false;
  bool showPerms = false;
  bool showIocs = false;

  @override
  Widget build(BuildContext context) {
    final analysis = widget.result?.analysis ?? {};
    final permissions = (analysis['permissions'] is List) ? List<String>.from(analysis['permissions']) : <String>[];
    final dangerous = (analysis['dangerous_permissions'] is List) ? List<String>.from(analysis['dangerous_permissions']) : <String>[];
    final certFingerprint = analysis['cert_fingerprint']?.toString() ?? '—';
    final certTrusted = analysis['cert_trusted_match']?.toString() ?? '—';
    final entropy = analysis['entropy_classes_dex']?.toString() ?? '—';
    final suspicious = analysis['suspicious'] ?? {};
    final suspiciousStrings = (suspicious['strings'] is List) ? List<String>.from(suspicious['strings']) : <String>[];
    final iconSim = analysis['icon_similarity_score']?.toString() ?? '—';
    final sha256 = widget.result?.meta?['sha256']?.toString() ?? '—';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _TabHeader(
          title: 'Static analysis',
          subtitle: 'Manifest, certificate, icon similarity, entropy, and suspicious string inspection.',
        ),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) {
            final narrow = constraints.maxWidth < 900;
            final left = Column(
              children: [
                _expandableCard(
                  title: 'Dangerous permissions',
                  accent: Colors.redAccent,
                  expanded: showDanger,
                  onToggle: () => setState(() => showDanger = !showDanger),
                  child: _chips(dangerous, showDanger ? dangerous.length : 5, Colors.redAccent),
                ),
                const SizedBox(height: 12),
                _expandableCard(
                  title: 'Permissions',
                  accent: const Color(0xFF0EA5A4),
                  expanded: showPerms,
                  onToggle: () => setState(() => showPerms = !showPerms),
                  child: _chips(permissions, showPerms ? permissions.length : 8, Colors.white70),
                ),
                const SizedBox(height: 12),
                _infoCard(
                  title: 'Signature & certificate',
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Trusted match: $certTrusted', style: TextStyle(color: Colors.white.withOpacity(0.70))),
                      const SizedBox(height: 10),
                      SelectableText(
                        certFingerprint,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Colors.white70),
                      ),
                    ],
                  ),
                ),
              ],
            );

            final right = Column(
              children: [
                _infoCard(
                  title: 'Icon similarity',
                  child: Column(
                    children: [
                      Container(
                        width: 96,
                        height: 96,
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(24),
                          gradient: LinearGradient(
                            colors: [Colors.white.withOpacity(0.06), Colors.white.withOpacity(0.02)],
                          ),
                        ),
                        child: Center(
                          child: Text(
                            iconSim,
                            style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text('Similarity score', style: TextStyle(color: Colors.white.withOpacity(0.60))),
                    ],
                  ),
                ),
                const SizedBox(height: 12),
                _infoCard(
                  title: 'Hashes',
                  child: SingleChildScrollView(
                    scrollDirection: Axis.horizontal,
                    child: SelectableText(
                      sha256,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Colors.white70),
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                _infoCard(
                  title: 'Entropy (classes.dex)',
                  child: Text(
                    entropy,
                    style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: Color(0xFF0EA5A4)),
                  ),
                ),
                const SizedBox(height: 12),
                _expandableCard(
                  title: 'Suspicious strings & IOCs',
                  accent: const Color(0xFF7C3AED),
                  expanded: showIocs,
                  onToggle: () => setState(() => showIocs = !showIocs),
                  child: _chips(suspiciousStrings, showIocs ? suspiciousStrings.length : 6, Colors.cyanAccent),
                ),
              ],
            );

            return narrow
                ? Column(
              children: [
                left,
                const SizedBox(height: 12),
                right,
              ],
            )
                : Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: left),
                const SizedBox(width: 12),
                SizedBox(width: 360, child: right),
              ],
            );
          },
        ),
      ],
    );
  }

  Widget _chips(List<String> items, int limit, Color color) {
    final showItems = items.take(limit).toList();
    if (showItems.isEmpty) {
      return Text('—', style: TextStyle(color: Colors.white.withOpacity(0.55)));
    }
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: showItems
          .map(
            (item) => Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.10),
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: color.withOpacity(0.20)),
          ),
          child: Text(
            item,
            style: TextStyle(fontSize: 12, color: color),
          ),
        ),
      )
          .toList(),
    );
  }

  Widget _expandableCard({
    required String title,
    required Color accent,
    required bool expanded,
    required VoidCallback onToggle,
    required Widget child,
  }) {
    return _infoCard(
      title: title,
      trailing: TextButton(
        onPressed: onToggle,
        child: Text(expanded ? 'Show less' : 'Show more'),
      ),
      child: AnimatedSize(
        duration: const Duration(milliseconds: 260),
        curve: Curves.easeOut,
        child: child,
      ),
    );
  }

  Widget _infoCard({
    required String title,
    required Widget child,
    Widget? trailing,
  }) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: _sectionLabel(title)),
              if (trailing != null) trailing,
            ],
          ),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _MlTab extends StatelessWidget {
  final AnalysisResult? result;
  const _MlTab({required this.result});

  double get mlProb {
    final v = result?.model?['probability_fake'];
    if (v is num) return v.toDouble();
    if (v is String) return double.tryParse(v) ?? 0.0;
    return 0.0;
  }

  List<String> get explanations {
    final raw = result?.model?['explanations'];
    if (raw is List) return List<String>.from(raw.map((e) => e.toString()));
    return [];
  }

  List<Map<String, dynamic>> get shapBars {
    final features = <String, double>{};
    for (var i = 0; i < explanations.length; i++) {
      final s = explanations[i];
      final match = RegExp(r'High\s+([a-zA-Z0-9_]+)').firstMatch(s);
      final feat = match != null ? match.group(1) ?? 'feat$i' : 'feat$i';
      features[feat] = (features[feat] ?? 0.0) + (explanations.length - i).toDouble();
    }
    final list = features.entries.map((e) => {'name': e.key, 'value': e.value}).toList();
    list.sort((a, b) => (b['value'] as double).compareTo(a['value'] as double));
    return list.take(8).toList();
  }

  @override
  Widget build(BuildContext context) {
    final probability = mlProb.clamp(0.0, 100.0);
    final shap = shapBars;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _TabHeader(
          title: 'ML analysis',
          subtitle: 'Model score, probability donut, and explanation-derived feature importance.',
        ),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) {
            final narrow = constraints.maxWidth < 900;
            final donut = _infoCard(
              title: 'ML probability',
              child: Column(
                children: [
                  SizedBox(
                    height: 220,
                    child: PieChart(
                      PieChartData(
                        centerSpaceRadius: 70,
                        sectionsSpace: 2,
                        sections: [
                          PieChartSectionData(
                            value: probability,
                            title: '${probability.toStringAsFixed(1)}%',
                            radius: 62,
                            titleStyle: const TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
                          ),
                          PieChartSectionData(
                            value: (100 - probability),
                            title: '',
                            radius: 52,
                            color: Colors.white.withOpacity(0.06),
                          ),
                        ],
                      ),
                    ),
                  ),
                  Text(
                    '${probability.toStringAsFixed(2)}% probability of being fake',
                    style: TextStyle(color: Colors.white.withOpacity(0.72)),
                  ),
                ],
              ),
            );

            final shapCard = _infoCard(
              title: 'Feature importance',
              child: SizedBox(
                height: 220,
                child: shap.isEmpty
                    ? Center(
                  child: Text(
                    'No explanations available',
                    style: TextStyle(color: Colors.white.withOpacity(0.55)),
                  ),
                )
                    : BarChart(
                  BarChartData(
                    maxY: shap.map((e) => e['value'] as double).reduce((a, b) => a > b ? a : b) + 2,
                    gridData: const FlGridData(show: false),
                    borderData: FlBorderData(show: false),
                    titlesData: FlTitlesData(
                      show: true,
                      leftTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      bottomTitles: AxisTitles(
                        sideTitles: SideTitles(
                          showTitles: true,
                          reservedSize: 36,
                          getTitlesWidget: (v, meta) {
                            final idx = v.toInt();
                            if (idx < shap.length) {
                              return Padding(
                                padding: const EdgeInsets.only(top: 8),
                                child: Text(
                                  shap[idx]['name'] as String,
                                  style: const TextStyle(fontSize: 10),
                                ),
                              );
                            }
                            return const SizedBox.shrink();
                          },
                        ),
                      ),
                    ),
                    barGroups: List.generate(
                      shap.length,
                          (i) => BarChartGroupData(
                        x: i,
                        barRods: [
                          BarChartRodData(
                            toY: shap[i]['value'] as double,
                            width: 18,
                            borderRadius: BorderRadius.circular(8),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            );

            return narrow
                ? Column(children: [donut, const SizedBox(height: 12), shapCard])
                : Row(children: [Expanded(child: donut), const SizedBox(width: 12), Expanded(child: shapCard)]);
          },
        ),
        const SizedBox(height: 12),
        _infoCard(
          title: 'Explanations',
          child: explanations.isEmpty
              ? Text('—', style: TextStyle(color: Colors.white.withOpacity(0.55)))
              : Column(
            children: explanations
                .map(
                  (e) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('• ', style: TextStyle(color: Colors.white.withOpacity(0.7))),
                    Expanded(child: Text(e, style: const TextStyle(color: Colors.white70))),
                  ],
                ),
              ),
            )
                .toList(),
          ),
        ),
      ],
    );
  }

  Widget _infoCard({required String title, required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionLabel(title),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _IntelTab extends StatelessWidget {
  final AnalysisResult? result;
  const _IntelTab({required this.result});

  @override
  Widget build(BuildContext context) {
    final vt = result?.analysis?['vt'];
    final mb = result?.analysis?['malwarebazaar'];
    final indicators = result?.analysis?['suspicious'] ?? {};

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _TabHeader(
          title: 'Threat intelligence',
          subtitle: 'External verdicts and indicator summaries in a premium dashboard layout.',
        ),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) {
            final narrow = constraints.maxWidth < 900;
            final left = Column(
              children: [
                _intelMiniCard(
                  title: 'VirusTotal',
                  icon: Icons.security_rounded,
                  detections: vt,
                ),
                const SizedBox(height: 12),
                _intelMiniCard(
                  title: 'MalwareBazaar',
                  icon: Icons.bug_report_rounded,
                  detections: mb,
                ),
              ],
            );

            final right = _infoCard(
              title: 'Indicators',
              child: indicators is Map
                  ? Column(
                children: [
                  _indicatorRow(Icons.public_rounded, 'IPs', '${indicators['ip_count'] ?? 0}'),
                  _indicatorRow(Icons.link_rounded, 'URLs', '${indicators['url_count'] ?? 0}'),
                  _indicatorRow(Icons.text_fields_rounded, 'Strings', '${(indicators['strings'] as List?)?.length ?? 0}'),
                ],
              )
                  : Text('—', style: TextStyle(color: Colors.white.withOpacity(0.55))),
            );

            final raw = Column(
              children: [
                _rawCard('VirusTotal raw', result?.analysis?['vt']?.toString() ?? '—'),
                const SizedBox(height: 12),
                _rawCard('MalwareBazaar raw', result?.analysis?['malwarebazaar']?.toString() ?? '—'),
              ],
            );

            if (narrow) {
              return Column(
                children: [
                  left,
                  const SizedBox(height: 12),
                  right,
                  const SizedBox(height: 12),
                  raw,
                ],
              );
            }

            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    children: [
                      left,
                      const SizedBox(height: 12),
                      raw,
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(child: right),
              ],
            );
          },
        ),
      ],
    );
  }

  Widget _intelMiniCard({
    required String title,
    required IconData icon,
    required dynamic detections,
  }) {
    final detected = detections is Map ? (detections['detections'] ?? detections['positives'] ?? 0) : 0;
    final total = detections is Map ? (detections['total'] ?? detections['total_scans'] ?? detections['scan_count'] ?? 0) : 0;
    final d = detected is num ? detected.toDouble() : double.tryParse(detected.toString()) ?? 0.0;
    final t = total is num ? total.toDouble() : double.tryParse(total.toString()) ?? 0.0;
    final progress = t > 0 ? (d / t).clamp(0.0, 1.0) : 0.0;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: const Color(0xFF0EA5A4).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Icon(icon, color: const Color(0xFF0EA5A4)),
              ),
              const SizedBox(width: 12),
              Expanded(child: _sectionLabel(title)),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            '$d / ${t == 0 ? "—" : t} detected',
            style: TextStyle(color: Colors.white.withOpacity(0.70)),
          ),
          const SizedBox(height: 12),
          ClipRRect(
            borderRadius: BorderRadius.circular(999),
            child: LinearProgressIndicator(
              value: progress,
              minHeight: 12,
              backgroundColor: Colors.white.withOpacity(0.08),
              valueColor: const AlwaysStoppedAnimation(Color(0xFF7C3AED)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _indicatorRow(IconData icon, String label, String value) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.03),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: [
          Icon(icon, size: 18, color: Colors.white70),
          const SizedBox(width: 10),
          Expanded(child: Text(label, style: const TextStyle(color: Colors.white70))),
          Text(value, style: const TextStyle(fontWeight: FontWeight.w700)),
        ],
      ),
    );
  }

  Widget _rawCard(String title, String text) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionLabel(title),
          const SizedBox(height: 12),
          Text(
            text,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Colors.white70),
          ),
        ],
      ),
    );
  }

  Widget _infoCard({required String title, required Widget child}) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: _cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _sectionLabel(title),
          const SizedBox(height: 12),
          child,
        ],
      ),
    );
  }
}

class _YaraTab extends StatefulWidget {
  final TextEditingController yaraController;
  final VoidCallback onCopy;
  final Future<void> Function() onSave;

  const _YaraTab({
    required this.yaraController,
    required this.onCopy,
    required this.onSave,
  });

  @override
  State<_YaraTab> createState() => _YaraTabState();
}

class _YaraTabState extends State<_YaraTab> {
  late final ScrollController _scrollController;

  @override
  void initState() {
    super.initState();
    _scrollController = ScrollController();
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _TabHeader(
          title: 'Generated YARA rule',
          subtitle: 'Review, copy, or save the rule generated from the latest analysis run.',
        ),
        const SizedBox(height: 16),
        Container(
          padding: const EdgeInsets.all(18),
          decoration: _cardDecoration(),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              TextField(
                controller: widget.yaraController,
                maxLines: 18,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 13,
                  color: Colors.white,
                ),
                decoration: InputDecoration(
                  filled: true,
                  fillColor: Colors.white.withOpacity(0.02),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(18),
                    borderSide: BorderSide(color: Colors.white.withOpacity(0.06)),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(18),
                    borderSide: BorderSide(color: Colors.white.withOpacity(0.06)),
                  ),
                  focusedBorder: const OutlineInputBorder(
                    borderRadius: BorderRadius.all(Radius.circular(18)),
                    borderSide: BorderSide(color: Color(0xFF0EA5A4)),
                  ),
                  hintText: 'No rule generated yet',
                  hintStyle: TextStyle(color: Colors.white.withOpacity(0.35)),
                  contentPadding: const EdgeInsets.all(18),
                ),
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  const Expanded(
                    child: Text(
                      'A clean, deploy-ready draft is generated from static indicators.',
                      style: TextStyle(color: Colors.white70),
                    ),
                  ),
                  const SizedBox(width: 10),
                  FilledButton.icon(
                    onPressed: widget.onSave,
                    icon: const Icon(Icons.download_rounded),
                    label: const Text('Save'),
                  ),
                  const SizedBox(width: 10),
                  OutlinedButton.icon(
                    onPressed: widget.onCopy,
                    icon: const Icon(Icons.copy_rounded),
                    label: const Text('Copy'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _TabHeader extends StatelessWidget {
  final String title;
  final String subtitle;

  const _TabHeader({
    required this.title,
    required this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w800)),
        const SizedBox(height: 6),
        Text(subtitle, style: TextStyle(color: Colors.white.withOpacity(0.65), height: 1.35)),
      ],
    );
  }
}

Decoration _cardDecoration() {
  return BoxDecoration(
    borderRadius: BorderRadius.circular(24),
    gradient: LinearGradient(
      colors: [
        Colors.white.withOpacity(0.05),
        Colors.white.withOpacity(0.025),
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    border: Border.all(color: Colors.white.withOpacity(0.06)),
    boxShadow: [
      BoxShadow(
        color: Colors.black.withOpacity(0.22),
        blurRadius: 26,
        offset: const Offset(0, 16),
      ),
    ],
  );
}

Widget _sectionLabel(String text) {
  return Text(
    text,
    style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700),
  );
}

Widget _statCard(String title, String value) {
  return Container(
    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
    decoration: BoxDecoration(
      color: Colors.white.withOpacity(0.03),
      borderRadius: BorderRadius.circular(18),
      border: Border.all(color: Colors.white.withOpacity(0.05)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.55))),
        const SizedBox(height: 6),
        Text(value, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
      ],
    ),
  );
}

Widget _infoCard(String title, Widget child) {
  return Container(
    width: double.infinity,
    padding: const EdgeInsets.all(18),
    decoration: _cardDecoration(),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _sectionLabel(title),
        const SizedBox(height: 12),
        child,
      ],
    ),
  );
}

class _VTBarChart extends StatelessWidget {
  final double detections;
  final double total;

  const _VTBarChart({required this.detections, required this.total});

  @override
  Widget build(BuildContext context) {
    final safe = (total - detections).clamp(0.0, total == 0 ? 1.0 : total);
    final totalNonZero = total == 0 ? 1.0 : total;
    return BarChart(
      BarChartData(
        alignment: BarChartAlignment.center,
        titlesData: FlTitlesData(
          show: true,
          bottomTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              reservedSize: 34,
              getTitlesWidget: (v, meta) {
                final idx = v.toInt();
                if (idx == 0) {
                  return const Text('Detections', style: TextStyle(fontSize: 11));
                }
                if (idx == 1) {
                  return const Text('Other', style: TextStyle(fontSize: 11));
                }
                return const SizedBox.shrink();
              },
            ),
          ),
          topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          leftTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
        ),
        gridData: const FlGridData(show: false),
        borderData: FlBorderData(show: false),
        barGroups: [
          BarChartGroupData(
            x: 0,
            barRods: [
              BarChartRodData(
                toY: detections,
                width: 20,
                borderRadius: BorderRadius.circular(10),
              ),
            ],
          ),
          BarChartGroupData(
            x: 1,
            barRods: [
              BarChartRodData(
                toY: safe,
                width: 20,
                borderRadius: BorderRadius.circular(10),
              ),
            ],
          ),
        ],
        minY: 0,
        maxY: totalNonZero,
      ),
    );
  }
}

class _IocBarChart extends StatelessWidget {
  final double ipCount;
  final double urlCount;
  final double stringsCount;

  const _IocBarChart({
    required this.ipCount,
    required this.urlCount,
    required this.stringsCount,
  });

  @override
  Widget build(BuildContext context) {
    final maxVal = [ipCount, urlCount, stringsCount, 1.0].reduce((a, b) => a > b ? a : b);
    return BarChart(
      BarChartData(
        maxY: maxVal == 0 ? 1 : maxVal + (maxVal * 0.2),
        titlesData: FlTitlesData(
          leftTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
          bottomTitles: AxisTitles(
            sideTitles: SideTitles(
              showTitles: true,
              reservedSize: 34,
              getTitlesWidget: (v, meta) {
                if (v.toInt() == 0) return const Text('IPs', style: TextStyle(fontSize: 11));
                if (v.toInt() == 1) return const Text('URLs', style: TextStyle(fontSize: 11));
                if (v.toInt() == 2) return const Text('Strings', style: TextStyle(fontSize: 11));
                return const SizedBox.shrink();
              },
            ),
          ),
        ),
        borderData: FlBorderData(show: false),
        gridData: const FlGridData(show: false),
        barGroups: [
          BarChartGroupData(x: 0, barRods: [BarChartRodData(toY: ipCount, width: 18)]),
          BarChartGroupData(x: 1, barRods: [BarChartRodData(toY: urlCount, width: 18)]),
          BarChartGroupData(x: 2, barRods: [BarChartRodData(toY: stringsCount, width: 18)]),
        ],
      ),
    );
  }
}

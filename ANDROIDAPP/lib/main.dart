import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:file_picker/file_picker.dart';
import 'package:percent_indicator/percent_indicator.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const SecureAPKApp());
}

const String apiAnalyzeUrl = "http://10.0.2.2:5000/analyze";
const String apiHealthUrl = "http://10.0.2.2:5000/health";

class SecureAPKApp extends StatelessWidget {
  const SecureAPKApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'SecureAPK',
      theme: ThemeData(
        brightness: Brightness.dark,
        fontFamily: 'Inter',
        scaffoldBackgroundColor: Colors.transparent,
        textTheme: const TextTheme(bodyMedium: TextStyle(color: Colors.white)),
      ),
      home: const HomePage(),
      debugShowCheckedModeBanner: false,
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

class HomePage extends StatefulWidget {
  const HomePage({Key? key}) : super(key: key);
  @override
  State<HomePage> createState() => _HomePageState();
}

enum TabItem { overview, staticTab, ml, intel, yara }

class _HomePageState extends State<HomePage> {
  TabItem _current = TabItem.overview;
  AnalysisResult? _result;
  bool _isUploading = false;
  double _uploadProgress = 0.0;
  String? _currentFileName;
  List<Map<String, dynamic>> _sessionLog = [];
  String _apiStatus = "unknown";
  Timer? _progressTimer;
  TextEditingController _yaraController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _checkApiHealth();
  }

  Future<void> _checkApiHealth() async {
    try {
      final resp = await http.get(Uri.parse(apiHealthUrl)).timeout(const Duration(seconds: 3));
      if (resp.statusCode == 200) {
        final j = jsonDecode(resp.body);
        setState(() => _apiStatus = j['status']?.toString() ?? 'ok');
      } else {
        setState(() => _apiStatus = 'down');
      }
    } catch (_) {
      setState(() => _apiStatus = 'down');
    }
  }

  Future<void> _pickAndUploadApk() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['apk'],
        withReadStream: true,
      );

      if (result == null) return;

      final fileBytes = result.files.single.bytes;
      final path = result.files.single.path;
      final name = result.files.single.name;

      setState(() {
        _currentFileName = name;
      });

      if (path == null && fileBytes == null) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Failed to pick file path.')));
        return;
      }

      File file;
      if (path != null) {
        file = File(path);
      } else {
        // write to temp file
        final tmp = await getTemporaryDirectory();
        final tmpFile = File('${tmp.path}/$name');
        await tmpFile.writeAsBytes(fileBytes!);
        file = tmpFile;
      }

      await _uploadFile(file);
    } catch (e) {
      debugPrint("pick error: $e");
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error picking file: $e')));
    }
  }

  Future<void> _uploadFile(File file) async {
    setState(() {
      _isUploading = true;
      _uploadProgress = 0.02;
    });

    // animate pseudo progress while server processes
    _startPseudoProgress();

    try {
      final uri = Uri.parse(apiAnalyzeUrl);
      final request = http.MultipartRequest('POST', uri);
      final fileLength = await file.length();
      final stream = http.ByteStream(file.openRead());
      final multipartFile = http.MultipartFile('file', stream, fileLength, filename: file.path.split('/').last);
      request.files.add(multipartFile);

      final streamedResponse = await request.send().timeout(const Duration(seconds: 120));
      final respStr = await streamedResponse.stream.bytesToString();

      if (streamedResponse.statusCode == 200) {
        final Map<String, dynamic> j = jsonDecode(respStr);
        final newResult = AnalysisResult.fromJson(j);

        // generate yara if not present
        String yaraText = _generateYaraText(newResult, fallbackIfMissing: true);

        setState(() {
          _result = newResult;
          _yaraController.text = yaraText;
          _sessionLog.insert(0, {
            'name': file.path.split('/').last,
            'time': DateTime.now().toIso8601String(),
            'sha256': newResult.meta?['sha256'] ?? '—'
          });
        });

        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Analysis complete')));
      } else {
        debugPrint('Upload failed ${streamedResponse.statusCode} $respStr');
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Upload failed: ${streamedResponse.statusCode}')));
      }
    } catch (e) {
      debugPrint('upload error: $e');
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error uploading file: $e')));
    } finally {
      _stopPseudoProgress();
      setState(() {
        _isUploading = false;
        _uploadProgress = 1.0;
      });
      Future.delayed(const Duration(milliseconds: 600), () {
        setState(() {
          _uploadProgress = 0.0;
        });
      });
      _checkApiHealth();
    }
  }

  void _startPseudoProgress() {
    _progressTimer?.cancel();
    _progressTimer = Timer.periodic(const Duration(milliseconds: 250), (t) {
      setState(() {
        // increase until 0.9
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
    setState(() {
      _uploadProgress = 0.95;
    });
  }

  String _generateYaraText(AnalysisResult? r, {bool fallbackIfMissing = false}) {
    // If backend already provides a yara rule in analysis, use it.
    if (r == null) return '';
    final analysis = r.analysis ?? {};
    if (analysis.containsKey('yara') && analysis['yara'] is String && (analysis['yara'] as String).isNotEmpty) {
      return analysis['yara'];
    }
    // Build basic yara from suspicious strings and package/app_label
    final appLabel = r.meta?['app_label'] ?? r.meta?['package'] ?? 'unknown_app';
    final suspicious = analysis['suspicious'] ?? {};
    final List<dynamic> strings = (suspicious['strings'] is List) ? List<dynamic>.from(suspicious['strings']) : [];
    final List<String> tokens = [];
    for (var s in strings.take(12)) {
      final ss = s.toString().trim();
      if (ss.length > 3) tokens.add(ss.replaceAll('"', ''));
    }
    final ruleName = 'SecureAPK_${appLabel.toString().replaceAll(RegExp(r'[^a-zA-Z0-9_]'), '_')}';
    final buffer = StringBuffer();
    buffer.writeln('rule $ruleName {');
    buffer.writeln('  meta:');
    buffer.writeln('    description = "Auto-generated YARA from SecureAPK mobile analysis"');
    buffer.writeln('    source = "SecureAPK-flutter-client"');
    buffer.writeln('  strings:');
    if (tokens.isEmpty) {
      buffer.writeln('    \$s0 = "SecureAPK_placeholder"');
    } else {
      for (var i = 0; i < tokens.length; i++) {
        final t = tokens[i];
        final key = '\$s$i';
        buffer.writeln('    $key = "${t}" nocase');
      }
    }
    buffer.writeln('  condition:');
    if (tokens.isEmpty) {
      buffer.writeln('    false');
    } else {
      buffer.writeln('    any of them');
    }
    buffer.writeln('}');
    return buffer.toString();
  }

  // Helper to safely get nested values
  dynamic _safe(Map? m, String key, [dynamic fallback]) {
    if (m == null) return fallback;
    return m.containsKey(key) ? m[key] : fallback;
  }

  Widget _buildScaffoldBody() {
    switch (_current) {
      case TabItem.overview:
        return _OverviewTab(result: _result);
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
      default:
        return const SizedBox();
    }
  }

  Future<void> _copyYaraToClipboard() async {
    final text = _yaraController.text;
    if (text.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('YARA copied to clipboard')));
  }

  Future<void> _saveYaraToFile() async {
    final text = _yaraController.text;
    if (text.isEmpty) return;
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/SecureAPK_rule_${DateTime.now().millisecondsSinceEpoch}.yar');
      await file.writeAsString(text);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Saved to ${file.path}')));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed saving: $e')));
    }
  }

  @override
  void dispose() {
    _progressTimer?.cancel();
    _yaraController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // gradient background and glass container
    return Scaffold(
      extendBodyBehindAppBar: true,
      appBar: AppBar(
        title: Row(children: [
          // Container(
          //   width: 36,
          //   height: 36,
          //   decoration: BoxDecoration(
          //     gradient: const LinearGradient(colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)]),
          //     borderRadius: BorderRadius.circular(10),
          //     boxShadow: [BoxShadow(color: Colors.white.withOpacity(0.06), blurRadius: 12, spreadRadius: 1)],
          //   ),
          //   child: const Icon(Icons.shield, size: 20, color: Colors.white),
          // ),
          // const SizedBox(width: 12),
          // const Text('SecureAPK'),
          // const SizedBox(width: 12),
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF7C3AED), Color(0xFF0EA5A4)],
              ),
              borderRadius: BorderRadius.circular(10),
              boxShadow: [
                BoxShadow(
                  color: Colors.white.withOpacity(0.06),
                  blurRadius: 12,
                  spreadRadius: 1,
                ),
              ],
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(10), // logo ko container ke shape me clip karega
              child: Image.asset(
                "assets/logo.png",
                fit: BoxFit.cover, // ya BoxFit.fill try karo agar stretch chahiye
              ),
            ),
          ),
          const SizedBox(width: 12),
          const Text(
            'SecureAPK',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
          ),
          const SizedBox(width: 8),
          // file name should not overflow: wrap it with Expanded and ellipsis
          Expanded(
            child: Text(
              _currentFileName == null ? 'No APK uploaded' : (_currentFileName ?? 'No APK uploaded'),
              style: const TextStyle(fontSize: 12, color: Colors.white70),
              overflow: TextOverflow.ellipsis,
              maxLines: 1,
            ),
          ),
        ]),
        actions: [
          Container(
            margin: const EdgeInsets.only(right: 12),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: _apiStatus == 'ok' ? Colors.green.withOpacity(0.12) : Colors.red.withOpacity(0.12),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(children: [
              Container(width: 8, height: 8, decoration: BoxDecoration(color: _apiStatus == 'ok' ? Colors.green : Colors.red, shape: BoxShape.circle)),
              const SizedBox(width: 8),
              Text('API: $_apiStatus', style: const TextStyle(fontSize: 12)),
            ]),
          )
        ],
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFF041021), Color(0xFF071024), Color(0xFF071C2A)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        child: SafeArea(
          child: Stack(
            children: [
              // main content
              Padding(
                padding: const EdgeInsets.only(bottom: 76.0),
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(18),
                  physics: const BouncingScrollPhysics(),
                  child: _buildScaffoldBody(),
                ),
              ),

              // bottom nav
              Positioned(
                left: 16,
                right: 16,
                bottom: 16,
                child: Container(
                  height: 64,
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.03),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: Colors.white.withOpacity(0.04)),
                    boxShadow: [BoxShadow(color: Colors.black.withOpacity(0.45), blurRadius: 10)],
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      _buildNavItem(Icons.dashboard, 'Overview', TabItem.overview),
                      _buildNavItem(Icons.folder, 'Static', TabItem.staticTab),
                      _buildNavItem(Icons.memory, 'ML', TabItem.ml),
                      _buildNavItem(Icons.search, 'Intel', TabItem.intel),
                      _buildNavItem(Icons.code, 'YARA', TabItem.yara),
                    ],
                  ),
                ),
              ),

              // FAB for upload
              Positioned(
                right: 26,
                bottom: 92,
                child: FloatingActionButton.extended(
                  onPressed: _isUploading ? null : _pickAndUploadApk,
                  label: Text(_isUploading ? 'Analyzing...' : 'Upload APK'),
                  icon: const Icon(Icons.upload_file),
                  backgroundColor: const Color(0xFF0EA5A4),
                ),
              ),

              // uploading overlay with progress
              if (_isUploading)
                Positioned.fill(
                  child: Container(
                    color: Colors.black.withOpacity(0.45),
                    child: Center(
                      child: SizedBox(
                        width: 360,
                        child: Card(
                          color: Colors.black.withOpacity(0.6),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                          child: Padding(
                            padding: const EdgeInsets.all(16.0),
                            child: Column(mainAxisSize: MainAxisSize.min, children: [
                              const Text('Uploading & Analyzing…', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                              const SizedBox(height: 12),
                              LinearPercentIndicator(
                                lineHeight: 12.0,
                                percent: (_uploadProgress.clamp(0.0, 1.0)),
                                linearStrokeCap: LinearStrokeCap.roundAll,
                                backgroundColor: Colors.white.withOpacity(0.06),
                                progressColor: const Color(0xFF7C3AED),
                              ),
                              const SizedBox(height: 8),
                              Text('${(_uploadProgress * 100).clamp(0, 100).toStringAsFixed(0)}%'),
                            ]),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildNavItem(IconData icon, String label, TabItem item) {
    final active = _current == item;
    return InkWell(
      onTap: () {
        setState(() {
          _current = item;
        });
      },
      borderRadius: BorderRadius.circular(12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        decoration: BoxDecoration(
          color: active ? Colors.white.withOpacity(0.04) : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 20, color: active ? const Color(0xFF7C3AED) : Colors.white70),
            const SizedBox(height: 4),
            Text(label, style: TextStyle(fontSize: 11, color: active ? const Color(0xFF7C3AED) : Colors.white70)),
          ],
        ),
      ),
    );
  }
}

// ------------------ Overview Tab ------------------
class _OverviewTab extends StatelessWidget {
  final AnalysisResult? result;
  const _OverviewTab({Key? key, this.result}) : super(key: key);

  double get finalScore {
    if (result?.model != null && result!.model!.containsKey('final_score')) {
      final v = result!.model!['final_score'];
      if (v is num) return (v.toDouble() / 100.0).clamp(0.0, 1.0);
    }
    return 0.0;
  }

  double get mlProb {
    if (result?.model != null && result!.model!.containsKey('probability_fake')) {
      final v = result!.model!['probability_fake'];
      if (v is num) return (v.toDouble() / 100.0).clamp(0.0, 1.0);
      if (v is String) {
        return double.tryParse(v) != null ? (double.parse(v) / 100.0) : 0.0;
      }
    }
    return 0.0;
  }

  String get decision {
    return result?.model?['decision']?.toString() ?? '—';
  }

  int get vtDetections {
    final vt = result?.analysis?['vt'] ?? {};
    if (vt is Map) {
      final det = vt['detections'] ?? vt['positives'] ?? 0;
      if (det is num) return det.toInt();
      if (det is String) return int.tryParse(det) ?? 0;
    }
    return 0;
  }

  int get vtTotal {
    final vt = result?.analysis?['vt'] ?? {};
    if (vt is Map) {
      final t = vt['total'] ?? vt['total_scans'] ?? vt['scan_count'] ?? 0;
      if (t is num) return t.toInt();
      if (t is String) return int.tryParse(t) ?? 0;
    }
    return 0;
  }

  int get ipCount {
    final s = result?.analysis?['suspicious'] ?? {};
    if (s is Map) {
      final v = s['ip_count'] ?? 0;
      if (v is num) return v.toInt();
    }
    return 0;
  }

  int get urlCount {
    final s = result?.analysis?['suspicious'] ?? {};
    if (s is Map) {
      final v = s['url_count'] ?? 0;
      if (v is num) return v.toInt();
    }
    return 0;
  }

  String get entropy {
    final s = result?.analysis?['suspicious'] ?? {};
    if (s is Map) {
      final v = s['entropy'];
      if (v != null) return v.toString();
    }
    return "N/A";
  }

  int get suspiciousStringsCount {
    final s = result?.analysis?['suspicious'] ?? {};
    if (s is Map && s['strings'] is List) {
      return (s['strings'] as List).length;
    }
    return 0;
  }

  @override
  Widget build(BuildContext context) {
    // Make the entire tab scrollable so internal rows can expand safely on small screens
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // header
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'Analysis Result',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
              ),
              ElevatedButton.icon(
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Use Upload APK to analyze new file'),
                    ),
                  );
                },
                icon: const Icon(Icons.file_upload),
                label: const Text('Upload New'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF0EA5A4),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // main card: risk meter + score
          // Container(
          //   padding: const EdgeInsets.all(14),
          //   decoration: BoxDecoration(
          //     color: Colors.white.withOpacity(0.02),
          //     borderRadius: BorderRadius.circular(14),
          //   ),
          //   child: LayoutBuilder(
          //     builder: (context, constraints) {
          //       // Make layout adapt: if width is narrow stack vertically
          //       final isNarrow = constraints.maxWidth < 700;
          //       return isNarrow
          //           ? Column(
          //         crossAxisAlignment: CrossAxisAlignment.start,
          //         children: [
          //           Center(
          //             child: CircularPercentIndicator(
          //               radius: 80.0,
          //               lineWidth: 12.0,
          //               percent: finalScore,
          //               center: Text(
          //                 '${(finalScore * 100).toStringAsFixed(0)}%',
          //                 style: const TextStyle(
          //                   fontSize: 22,
          //                   fontWeight: FontWeight.bold,
          //                 ),
          //               ),
          //               progressColor: finalScore > 0.7
          //                   ? Colors.redAccent
          //                   : (finalScore > 0.4
          //                   ? Colors.orangeAccent
          //                   : Colors.greenAccent),
          //               backgroundColor: Colors.white.withOpacity(0.04),
          //               circularStrokeCap: CircularStrokeCap.round,
          //             ),
          //           ),
          //           const SizedBox(height: 8),
          //           Center(
          //             child: Text(
          //               decision,
          //               style: const TextStyle(
          //                 fontSize: 14,
          //                 color: Colors.white70,
          //               ),
          //             ),
          //           ),
          //           const SizedBox(height: 12),
          //           const Text(
          //             'Final Risk Score',
          //             style: TextStyle(color: Colors.white70),
          //           ),
          //           Text(
          //             '${(finalScore * 100).toStringAsFixed(2)}%',
          //             style: const TextStyle(
          //               fontSize: 28,
          //               fontWeight: FontWeight.bold,
          //             ),
          //           ),
          //           const SizedBox(height: 8),
          //           Wrap(
          //             spacing: 8,
          //             children: [
          //               ElevatedButton(
          //                 onPressed: () {
          //                   final state =
          //                   context.findAncestorStateOfType<
          //                       _HomePageState>();
          //                   state?.setState(() {
          //                     state._current = TabItem.ml;
          //                   });
          //                 },
          //                 style: ElevatedButton.styleFrom(
          //                   backgroundColor: const Color(0xFF0EA5A4),
          //                 ),
          //                 child: const Text('View ML'),
          //               ),
          //               OutlinedButton(
          //                 onPressed: () {
          //                   final state =
          //                   context.findAncestorStateOfType<
          //                       _HomePageState>();
          //                   state?.setState(() {
          //                     state._current = TabItem.staticTab;
          //                   });
          //                 },
          //                 child: const Text('View Static'),
          //               ),
          //             ],
          //           ),
          //           const SizedBox(height: 12),
          //           Wrap(
          //             spacing: 8,
          //             runSpacing: 8,
          //             children: [
          //               _smallKpi('Final Risk',
          //                   '${(finalScore * 100).toStringAsFixed(0)}%'),
          //               _smallKpi('VirusTotal',
          //                   '$vtDetections / ${vtTotal == 0 ? "—" : vtTotal}'),
          //               _smallKpi(
          //                   'MalwareBazaar',
          //                   (result?.analysis?['malwarebazaar']
          //                   ?['detections']
          //                       ?.toString() ??
          //                       '—')),
          //             ],
          //           ),
          //         ],
          //       )
          //           : Row(
          //         crossAxisAlignment: CrossAxisAlignment.center,
          //         children: [
          //           // gauge
          //           SizedBox(
          //             width: 180,
          //             child: Column(
          //               children: [
          //                 CircularPercentIndicator(
          //                   radius: 80.0,
          //                   lineWidth: 12.0,
          //                   percent: finalScore,
          //                   center: Text(
          //                     '${(finalScore * 100).toStringAsFixed(0)}%',
          //                     style: const TextStyle(
          //                       fontSize: 22,
          //                       fontWeight: FontWeight.bold,
          //                     ),
          //                   ),
          //                   progressColor: finalScore > 0.7
          //                       ? Colors.redAccent
          //                       : (finalScore > 0.4
          //                       ? Colors.orangeAccent
          //                       : Colors.greenAccent),
          //                   backgroundColor:
          //                   Colors.white.withOpacity(0.04),
          //                   circularStrokeCap: CircularStrokeCap.round,
          //                 ),
          //                 const SizedBox(height: 8),
          //                 Text(
          //                   decision,
          //                   style: const TextStyle(
          //                     fontSize: 14,
          //                     color: Colors.white70,
          //                   ),
          //                 ),
          //               ],
          //             ),
          //           ),
          //           const SizedBox(width: 18),
          //
          //           // score + buttons + small stats
          //           Expanded(
          //             child: Column(
          //               crossAxisAlignment: CrossAxisAlignment.start,
          //               children: [
          //                 const Text(
          //                   'Final Risk Score',
          //                   style: TextStyle(color: Colors.white70),
          //                 ),
          //                 const SizedBox(height: 6),
          //                 Text(
          //                   '${(finalScore * 100).toStringAsFixed(2)}%',
          //                   style: const TextStyle(
          //                     fontSize: 28,
          //                     fontWeight: FontWeight.bold,
          //                   ),
          //                 ),
          //                 const SizedBox(height: 8),
          //                 Wrap(
          //                   spacing: 8,
          //                   children: [
          //                     ElevatedButton(
          //                       onPressed: () {
          //                         final state = context
          //                             .findAncestorStateOfType<
          //                             _HomePageState>();
          //                         state?.setState(() {
          //                           state._current = TabItem.ml;
          //                         });
          //                       },
          //                       style: ElevatedButton.styleFrom(
          //                         backgroundColor: const Color(0xFF0EA5A4),
          //                       ),
          //                       child: const Text('View ML'),
          //                     ),
          //                     OutlinedButton(
          //                       onPressed: () {
          //                         final state = context
          //                             .findAncestorStateOfType<
          //                             _HomePageState>();
          //                         state?.setState(() {
          //                           state._current = TabItem.staticTab;
          //                         });
          //                       },
          //                       child: const Text('View Static'),
          //                     ),
          //                   ],
          //                 ),
          //                 const SizedBox(height: 12),
          //                 Row(
          //                   children: [
          //                     _smallKpi('Final Risk',
          //                         '${(finalScore * 100).toStringAsFixed(0)}%'),
          //                     const SizedBox(width: 8),
          //                     _smallKpi('VirusTotal',
          //                         '$vtDetections / ${vtTotal == 0 ? "—" : vtTotal}'),
          //                     const SizedBox(width: 8),
          //                     _smallKpi(
          //                         'MalwareBazaar',
          //                         (result?.analysis?['malwarebazaar']
          //                         ?['detections']
          //                             ?.toString() ??
          //                             '—')),
          //                   ],
          //                 ),
          //               ],
          //             ),
          //           )
          //         ],
          //       );
          //     },
          //   ),
          // ),
          // main card: risk meter + score
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.02),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.center, // sab center aligned
              children: [
                // Circular Gauge
                CircularPercentIndicator(
                  radius: 80.0,
                  lineWidth: 12.0,
                  percent: finalScore,
                  center: Text(
                    '${(finalScore * 100).toStringAsFixed(0)}%',
                    style: const TextStyle(
                      fontSize: 22,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  progressColor: finalScore > 0.7
                      ? Colors.redAccent
                      : (finalScore > 0.4
                      ? Colors.orangeAccent
                      : Colors.greenAccent),
                  backgroundColor: Colors.white.withOpacity(0.04),
                  circularStrokeCap: CircularStrokeCap.round,
                ),
                const SizedBox(height: 8),

                // Decision text
                Text(
                  decision,
                  style: const TextStyle(
                    fontSize: 14,
                    color: Colors.white70,
                  ),
                ),

                const SizedBox(height: 16),

                // Final Risk Score centered
                const Text(
                  'Final Risk Score',
                  style: TextStyle(color: Colors.white70),
                ),
                const SizedBox(height: 6),
                Text(
                  '${(finalScore * 100).toStringAsFixed(2)}%',
                  style: const TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.bold,
                  ),
                ),

                const SizedBox(height: 16),

                // Buttons Row: ML left, Static right
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Expanded(
                      child: ElevatedButton(
                        onPressed: () {
                          final state =
                          context.findAncestorStateOfType<_HomePageState>();
                          state?.setState(() {
                            state._current = TabItem.ml;
                          });
                        },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFF0EA5A4),
                        ),
                        child: const Text('View ML'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton(
                        onPressed: () {
                          final state =
                          context.findAncestorStateOfType<_HomePageState>();
                          state?.setState(() {
                            state._current = TabItem.staticTab;
                          });
                        },
                        child: const Text('View Static'),
                      ),
                    ),
                  ],
                ),

                const SizedBox(height: 16),

                // Bottom KPIs in equal width
                Row(
                  children: [
                    Expanded(
                      child: _smallKpi(
                        'Final Risk',
                        '${(finalScore * 100).toStringAsFixed(0)}%',
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: _smallKpi(
                        'VirusTotal',
                        '$vtDetections / ${vtTotal == 0 ? "—" : vtTotal}',
                      ),
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: _smallKpi(
                        'MalwareBazaar',
                        (result?.analysis?['malwarebazaar']?['detections']
                            ?.toString() ??
                            '—'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),


          const SizedBox(height: 12),

          // Charts row: VT bar and IOC chart
          LayoutBuilder(
            builder: (context, constraints) {
              final narrow = constraints.maxWidth < 700;
              return narrow
                  ? Column(
                children: [
                  _chartCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'VirusTotal',
                          style: TextStyle(
                              fontSize: 14, color: Colors.white70),
                        ),
                        const SizedBox(height: 8),
                        SizedBox(
                          height: 140,
                          child: _VTBarChart(
                            detections: vtDetections.toDouble(),
                            total: vtTotal.toDouble(),
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          'Detections: $vtDetections / ${vtTotal == 0 ? "—" : vtTotal}',
                          style:
                          const TextStyle(color: Colors.white54),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 10),
                  _chartCard(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'IOCs',
                          style: TextStyle(
                              fontSize: 14, color: Colors.white70),
                        ),
                        const SizedBox(height: 8),
                        SizedBox(
                          height: 140,
                          child: _IocBarChart(
                            ipCount: ipCount.toDouble(),
                            urlCount: urlCount.toDouble(),
                            stringsCount:
                            suspiciousStringsCount.toDouble(),
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          'IPs: $ipCount • URLs: $urlCount • Strings: $suspiciousStringsCount',
                          style:
                          const TextStyle(color: Colors.white54),
                        ),
                      ],
                    ),
                  ),
                ],
              )
                  : Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: _chartCard(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'VirusTotal',
                            style: TextStyle(
                                fontSize: 14, color: Colors.white70),
                          ),
                          const SizedBox(height: 8),
                          SizedBox(
                            height: 140,
                            child: _VTBarChart(
                              detections: vtDetections.toDouble(),
                              total: vtTotal.toDouble(),
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            'Detections: $vtDetections / ${vtTotal == 0 ? "—" : vtTotal}',
                            style: const TextStyle(color: Colors.white54),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _chartCard(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'IOCs',
                            style: TextStyle(
                                fontSize: 14, color: Colors.white70),
                          ),
                          const SizedBox(height: 8),
                          SizedBox(
                            height: 140,
                            child: _IocBarChart(
                              ipCount: ipCount.toDouble(),
                              urlCount: urlCount.toDouble(),
                              stringsCount:
                              suspiciousStringsCount.toDouble(),
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            'IPs: $ipCount • URLs: $urlCount • Strings: $suspiciousStringsCount',
                            style: const TextStyle(color: Colors.white54),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              );
            },
          ),
        ],
      ),
    );
  }


  Widget _chartCard({required Widget child}) {
    return Container(
      padding: const EdgeInsets.all(12),
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
      child: child,
    );
  }

  Widget _smallKpi(String title, String value) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(10)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: const TextStyle(fontSize: 11, color: Colors.white54)),
        const SizedBox(height: 4),
        Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
      ]),
    );
  }
}

// VT Bar Chart widget (simple)
class _VTBarChart extends StatelessWidget {
  final double detections;
  final double total;
  const _VTBarChart({Key? key, required this.detections, required this.total}) : super(key: key);

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
              getTitlesWidget: (v, meta) {
                final idx = v.toInt();
                if (idx == 0) {
                  return const Text('Detections', style: TextStyle(fontSize: 11));
                }
                if (idx == 1) {
                  return const Text('Other', style: TextStyle(fontSize: 11));
                }
                return const Text('');
              },
            ),
          ),
          topTitles: const AxisTitles(
            sideTitles: SideTitles(showTitles: false),
          ),
          leftTitles: const AxisTitles(
            sideTitles: SideTitles(showTitles: false),
          ),
          rightTitles: const AxisTitles(
            sideTitles: SideTitles(showTitles: false),
          ),
        ),
        gridData: const FlGridData(show: false),
        borderData: FlBorderData(show: false),
        barGroups: [
          BarChartGroupData(
            x: 0,
            barRods: [
              BarChartRodData(
                toY: detections,
                width: 18,
                borderRadius: BorderRadius.circular(6),
              ),
            ],
          ),
          BarChartGroupData(
            x: 1,
            barRods: [
              BarChartRodData(
                toY: safe,
                width: 18,
                borderRadius: BorderRadius.circular(6),
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

// IOC Bar Chart
class _IocBarChart extends StatelessWidget {
  final double ipCount;
  final double urlCount;
  final double stringsCount;
  const _IocBarChart({Key? key, required this.ipCount, required this.urlCount, required this.stringsCount}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final maxVal = [ipCount, urlCount, stringsCount, 1.0].reduce((a, b) => a > b ? a : b);
    return BarChart(
      BarChartData(
        maxY: maxVal == 0 ? 1 : maxVal + (maxVal * 0.2),
        titlesData: FlTitlesData(
          leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
          rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
          topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
          bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, getTitlesWidget: (v, meta) {
            if (v.toInt() == 0) return const Text('IPs', style: TextStyle(fontSize: 11));
            if (v.toInt() == 1) return const Text('URLs', style: TextStyle(fontSize: 11));
            if (v.toInt() == 2) return const Text('Strings', style: TextStyle(fontSize: 11));
            return const Text('');
          })),
        ),
        borderData: FlBorderData(show: false),
        gridData: FlGridData(show: false),
        barGroups: [
          BarChartGroupData(x: 0, barRods: [BarChartRodData(toY: ipCount, width: 14)]),
          BarChartGroupData(x: 1, barRods: [BarChartRodData(toY: urlCount, width: 14)]),
          BarChartGroupData(x: 2, barRods: [BarChartRodData(toY: stringsCount, width: 14)]),
        ],
      ),
    );
  }
}

// ------------------ Static Tab ------------------
class _StaticTab extends StatefulWidget {
  final AnalysisResult? result;
  const _StaticTab({Key? key, this.result}) : super(key: key);

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
    final iconSim = analysis['icon_similarity_score'] != null ? analysis['icon_similarity_score'].toString() : '—';
    final hashesBlock = widget.result?.meta?['sha256']?.toString() ?? '—';

    // Wrap the whole tab in a scroll view
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Static Analysis', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),

          LayoutBuilder(builder: (context, constraints) {
            final narrow = constraints.maxWidth < 900;
            return narrow
                ? Column(
              children: [
                _leftStaticColumn(permissions, dangerous, certFingerprint, certTrusted, entropy, suspiciousStrings),
                const SizedBox(height: 12),
                _rightStaticColumn(iconSim, hashesBlock,entropy),
              ],
            )
                : Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: _leftStaticColumn(permissions, dangerous, certFingerprint, certTrusted, entropy, suspiciousStrings)),
                const SizedBox(width: 12),
                SizedBox(width: 260, child: _rightStaticColumn(iconSim, hashesBlock, entropy)),
              ],
            );
          }),
        ],
      ),
    );
  }

  Widget _leftStaticColumn(List<String> permissions, List<String> dangerous, String certFingerprint, String certTrusted, String entropy, List<String> suspiciousStrings) {
    return Column(children: [
      // Dangerous perms
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            const Text('🚨 Dangerous Permissions', style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.bold)),
            TextButton(onPressed: () => setState(() => showDanger = !showDanger), child: Text(showDanger ? 'Hide' : 'Show more'))
          ]),
          const SizedBox(height: 6),
          AnimatedCrossFade(
            firstChild: _buildPermissionPreview(dangerous, limit: 3, dangerColor: true),
            secondChild: _buildPermissionFull(dangerous, dangerColor: true),
            crossFadeState: showDanger ? CrossFadeState.showSecond : CrossFadeState.showFirst,
            duration: const Duration(milliseconds: 300),
          ),
        ]),
      ),

      // Permissions
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            const Text('Permissions', style: TextStyle(color: Colors.white70, fontWeight: FontWeight.bold)),
            TextButton(onPressed: () => setState(() => showPerms = !showPerms), child: Text(showPerms ? 'Collapse' : 'Show more'))
          ]),
          const SizedBox(height: 6),
          AnimatedCrossFade(
            firstChild: _buildPermissionPreview(permissions, limit: 6),
            secondChild: _buildPermissionFull(permissions),
            crossFadeState: showPerms ? CrossFadeState.showSecond : CrossFadeState.showFirst,
            duration: const Duration(milliseconds: 300),
          ),
        ]),
      ),

      // Signature & cert
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            const Text('Signature & Certificates', style: TextStyle(color: Colors.white70, fontWeight: FontWeight.bold)),
            Text(certTrusted, style: const TextStyle(color: Colors.white70))
          ]),
          const SizedBox(height: 8),
          SelectableText('Fingerprint: $certFingerprint', style: const TextStyle(color: Colors.white60)),
        ]),
      ),

      const SizedBox(height: 12),

      // Suspicious Strings & IOCs
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
            const Text('Suspicious Strings & IOCs', style: TextStyle(color: Colors.white70, fontWeight: FontWeight.bold)),
            TextButton(onPressed: () => setState(() => showIocs = !showIocs), child: Text(showIocs ? 'Hide' : 'Show more'))
          ]),
          const SizedBox(height: 8),
          AnimatedCrossFade(
            firstChild: _buildPermissionPreview(suspiciousStrings, limit: 6),
            secondChild: _buildSuspiciousFull(suspiciousStrings),
            crossFadeState: showIocs ? CrossFadeState.showSecond : CrossFadeState.showFirst,
            duration: const Duration(milliseconds: 300),
          ),
        ]),
      ),
    ]);
  }

  Widget _rightStaticColumn(String iconSim, String hashesBlock, String entropy) {
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          margin: const EdgeInsets.only(bottom: 8),
          width: double.infinity,
          decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.center, children: [
            const Text('Icon Similarity', style: TextStyle(color: Colors.white70)),
            const SizedBox(height: 8),
            Container(
              width: 92,
              height: 92,
              decoration: BoxDecoration(color: Colors.white.withOpacity(0.03), borderRadius: BorderRadius.circular(12)),
              child: Center(child: Text(iconSim, style: const TextStyle(color: Colors.white70))),
            ),
            const SizedBox(height: 8),
            Text('Score: $iconSim', style: const TextStyle(color: Colors.white60)),
          ]),
        ),
        Container(
          padding: const EdgeInsets.all(12),
          margin: const EdgeInsets.only(bottom: 8),
          width: double.infinity,
          decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Hashes', style: TextStyle(color: Colors.white70)),
            const SizedBox(height: 8),
            // horizontal scroll for long hash line
            SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: SelectableText('SHA256: $hashesBlock', style: const TextStyle(color: Colors.white60)),
            ),
          ]),
        ),
        Container(
          padding: const EdgeInsets.all(12),
          width: double.infinity,
          decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Entropy (classes.dex)', style: TextStyle(color: Colors.white70)),
            const SizedBox(height: 8),
            Text(entropy, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          ]),
        ),
      ],
    );
  }

  Widget _buildPermissionPreview(List<String> items, {int limit = 3, bool dangerColor = false}) {
    if (items.isEmpty) return Text('—', style: TextStyle(color: dangerColor ? Colors.red.shade200 : Colors.white70));
    final preview = items.take(limit).toList();
    // use wrap with chips to avoid overflow
    return Wrap(
      spacing: 8,
      runSpacing: 6,
      children: preview.map((p) {
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
          decoration: BoxDecoration(
            color: dangerColor ? Colors.red.withOpacity(0.14) : Colors.white.withOpacity(0.02),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Text(p, style: TextStyle(color: dangerColor ? Colors.red.shade200 : Colors.white70, fontSize: 12)),
        );
      }).toList(),
    );
  }

  Widget _buildPermissionFull(List<String> items, {bool dangerColor = false}) {
    if (items.isEmpty) return Text('—', style: TextStyle(color: dangerColor ? Colors.red.shade200 : Colors.white70));
    return SizedBox(
      height: 160,
      child: SingleChildScrollView(
        child: Wrap(spacing: 8, runSpacing: 6, children: items.map((p) {
          return Container(
            width: 200,
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
            decoration: BoxDecoration(
              color: dangerColor ? Colors.red.withOpacity(0.12) : Colors.white.withOpacity(0.02),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(p, style: TextStyle(color: dangerColor ? Colors.red.shade200 : Colors.white70)),
          );
        }).toList()),
      ),
    );
  }

  Widget _buildSuspiciousFull(List<String> items) {
    if (items.isEmpty) return Text('—', style: const TextStyle(color: Colors.white54));
    return SizedBox(
      height: 160,
      child: SingleChildScrollView(child: Text(items.join('\n'), style: const TextStyle(color: Colors.white70))),
    );
  }
}

// ------------------ ML Tab ------------------
class _MlTab extends StatelessWidget {
  final AnalysisResult? result;
  const _MlTab({Key? key, this.result}) : super(key: key);

  double get mlProb {
    if (result?.model != null && result!.model!.containsKey('probability_fake')) {
      final v = result!.model!['probability_fake'];
      if (v is num) return v.toDouble();
      if (v is String) return double.tryParse(v) ?? 0.0;
    }
    return 0.0;
  }

  List<String> get explanations {
    final raw = result?.model?['explanations'];
    if (raw is List) {
      return List<String>.from(raw.map((e) => e.toString()));
    }
    return [];
  }

  // build synthetic SHAP values from explanations (best-effort)
  List<Map<String, dynamic>> get shapBars {
    final features = <String, double>{};
    for (var i = 0; i < explanations.length; i++) {
      final s = explanations[i];
      final match = RegExp(r'High\s+([a-zA-Z0-9_]+)').firstMatch(s);
      final feat = match != null ? match.group(1) ?? 'feat$i' : 'feat$i';
      features[feat] = (features[feat] ?? 0.0) + (explanations.length - i).toDouble();
    }
    // convert to list
    final list = features.entries.map((e) => {'name': e.key, 'value': e.value}).toList();
    list.sort((a, b) => (b['value'] as double).compareTo(a['value'] as double));
    return list.take(8).toList();
  }

  @override
  Widget build(BuildContext context) {
    final probability = mlProb; // percent (0-100)
    final probFraction = (probability / 100.0).clamp(0.0, 1.0);

    final shap = shapBars;
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('ML Analysis', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        LayoutBuilder(builder: (context, constraints) {
          final narrow = constraints.maxWidth < 700;
          return narrow
              ? Column(children: [
            _mlProbabilityCard(probability),
            const SizedBox(height: 10),
            _mlShapCard(shap),
          ])
              : Row(children: [
            Expanded(child: _mlProbabilityCard(probability)),
            const SizedBox(width: 12),
            Expanded(child: _mlShapCard(shap)),
          ]);
        }),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Explanations', style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            ...explanations.isEmpty ? [const Text('—', style: TextStyle(color: Colors.white54))] : explanations.map((e) => Padding(padding: const EdgeInsets.symmetric(vertical: 6), child: Text('• $e', style: const TextStyle(color: Colors.white70)))).toList()
          ]),
        )
      ]),
    );
  }

  Widget _mlProbabilityCard(double probability) {
    return Container(
      padding: const EdgeInsets.all(14),
      margin: const EdgeInsets.only(right: 8),
      decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
      child: Column(children: [
        const Text('ML Probability', style: TextStyle(color: Colors.white70)),
        const SizedBox(height: 8),
        SizedBox(
          height: 180,
          child: PieChart(PieChartData(
            centerSpaceRadius: 50,
            sections: [
              PieChartSectionData(value: probability.toDouble(), title: '${probability.toStringAsFixed(1)}%', radius: 48, titleStyle: const TextStyle(fontSize: 14, fontWeight: FontWeight.bold)),
              PieChartSectionData(value: (100 - probability.toDouble()), title: '', radius: 40, color: Colors.white.withOpacity(0.06)),
            ],
            sectionsSpace: 2,
          )),
        ),
        const SizedBox(height: 6),
        Text('${probability.toStringAsFixed(2)}% probability of being fake', style: const TextStyle(color: Colors.white70)),
      ]),
    );
  }

  Widget _mlShapCard(List<Map<String, dynamic>> shap) {
    return Container(
      padding: const EdgeInsets.all(14),
      margin: const EdgeInsets.only(left: 8),
      decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Feature Importance (SHAP-like)', style: TextStyle(color: Colors.white70)),
        const SizedBox(height: 8),
        SizedBox(
          height: 160,
          child: shap.isEmpty
              ? const Center(child: Text('No explanations available', style: TextStyle(color: Colors.white54)))
              : BarChart(BarChartData(
            maxY: shap.map((e) => e['value'] as double).reduce((a, b) => a > b ? a : b) + 2,
            titlesData: FlTitlesData(show: true, bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, getTitlesWidget: (v, meta) {
              final idx = v.toInt();
              if (idx < shap.length) {
                final name = shap[idx]['name'] as String;
                // Wrap bottom title in a container so it doesn't overflow horizontally
                return Padding(padding: const EdgeInsets.only(top: 6), child: Text(name, style: const TextStyle(fontSize: 10)));
              }
              return const Text('');
            }))),
            barGroups: List.generate(shap.length, (i) {
              final val = shap[i]['value'] as double;
              return BarChartGroupData(x: i, barRods: [BarChartRodData(toY: val, width: 14)]);
            }),
          )),
        )
      ]),
    );
  }
}

// ------------------ Intelligence Tab ------------------
class _IntelTab extends StatelessWidget {
  final AnalysisResult? result;
  const _IntelTab({Key? key, this.result}) : super(key: key);

  String prettyJson(dynamic obj) {
    try {
      final enc = const JsonEncoder.withIndent('  ');
      return enc.convert(obj);
    } catch (_) {
      return obj?.toString() ?? '—';
    }
  }

  @override
  Widget build(BuildContext context) {
    final vt = result?.analysis?['vt'];
    final mb = result?.analysis?['malwarebazaar'] ?? result?.analysis?['malwarebazaar'] ?? result?.analysis?['malwarebazaar'];
    final indicators = result?.analysis?['suspicious'] ?? {};
    // allow vertical scroll
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Threat Intelligence', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
        const SizedBox(height: 12),
        LayoutBuilder(builder: (context, constraints) {
          final narrow = constraints.maxWidth < 700;
          return narrow
              ? Column(children: [
            _intelCard(title: 'VirusTotal', content: vt == null ? '—' : prettyJson(vt)),
            const SizedBox(height: 8),
            _intelCard(title: 'MalwareBazaar', content: mb == null ? '—' : prettyJson(mb)),
          ])
              : Row(children: [
            Expanded(child: _intelCard(title: 'VirusTotal', content: vt == null ? '—' : prettyJson(vt))),
            const SizedBox(width: 12),
            Expanded(child: _intelCard(title: 'MalwareBazaar', content: mb == null ? '—' : prettyJson(mb))),
          ]);
        }),
        const SizedBox(height: 12),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Indicators', style: TextStyle(fontSize: 14, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            indicators is Map
                ? Column(children: [
              Row(children: [
                const Text('IPs', style: TextStyle(color: Colors.white70)),
                const SizedBox(width: 8),
                Text('${indicators['ip_count'] ?? 0}', style: const TextStyle(color: Colors.white)),
              ]),
              const SizedBox(height: 6),
              Row(children: [
                const Text('URLs', style: TextStyle(color: Colors.white70)),
                const SizedBox(width: 8),
                Text('${indicators['url_count'] ?? 0}', style: const TextStyle(color: Colors.white)),
              ]),
              const SizedBox(height: 8),
              // make long strings box scroll horizontally if needed
              SizedBox(
                height: 120,
                child: SingleChildScrollView(
                  child: SelectableText(indicators['strings'] != null ? (indicators['strings'] as List).take(100).join('\n') : '—', style: const TextStyle(color: Colors.white70)),
                ),
              ),
            ])
                : const Text('—', style: TextStyle(color: Colors.white54))
          ]),
        )
      ]),
    );
  }

  Widget _intelCard({required String title, required String content}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: Colors.white.withOpacity(0.02), borderRadius: BorderRadius.circular(12)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        // wrap raw JSON inside a box with both vertical & horizontal scroll
        Scrollbar(
          thumbVisibility: true,
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: ConstrainedBox(
              constraints: const BoxConstraints(minWidth: 300),
              child: SizedBox(
                width: 600,
                child: SingleChildScrollView(
                  child: SelectableText(content, style: const TextStyle(color: Colors.white70)),
                ),
              ),
            ),
          ),
        ),
      ]),
    );
  }
}

// ------------------ YARA Tab ------------------
class _YaraTab extends StatefulWidget {
  final TextEditingController yaraController;
  final VoidCallback onCopy;
  final Future<void> Function() onSave;
  const _YaraTab({Key? key, required this.yaraController, required this.onCopy, required this.onSave}) : super(key: key);

  @override
  State<_YaraTab> createState() => _YaraTabState();
}

class _YaraTabState extends State<_YaraTab> {
  late ScrollController _scrollController;

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
    return SingleChildScrollView(
      controller: _scrollController,
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Generated YARA Rule',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.02),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Scrollbar(
                  controller: _scrollController,
                  thumbVisibility: true,
                  child: SingleChildScrollView(
                    controller: _scrollController,
                    scrollDirection: Axis.horizontal,
                    child: SizedBox(
                      width: MediaQuery.of(context).size.width * 2, // extra width for long rules
                      child: TextField(
                        controller: widget.yaraController,
                        maxLines: 12,
                        decoration: const InputDecoration(
                          border: InputBorder.none,
                          hintText: 'No rule generated yet',
                          hintStyle: TextStyle(color: Colors.white24),
                        ),
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          color: Colors.white70,
                        ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: [
                    ElevatedButton.icon(
                      onPressed: widget.onSave,
                      icon: const Icon(Icons.download),
                      label: const Text('Download .yar'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF7C3AED),
                      ),
                    ),
                    OutlinedButton.icon(
                      onPressed: widget.onCopy,
                      icon: const Icon(Icons.copy),
                      label: const Text('Copy'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
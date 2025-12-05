import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// ============================================================================
// Extension Activation
// ============================================================================

export function activate(context: vscode.ExtensionContext) {
    console.log('Rust-cola extension activated');

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rustcola.scan', () => runScan(false)),
        vscode.commands.registerCommand('rustcola.scanWithReport', () => runScan(true))
    );

    // Register chat participant
    const chatParticipant = vscode.chat.createChatParticipant('rustcola.chat', handleChatRequest);
    chatParticipant.iconPath = vscode.Uri.joinPath(context.extensionUri, 'images', 'icon.png');
    context.subscriptions.push(chatParticipant);
}

export function deactivate() {}

// ============================================================================
// Scan Functions
// ============================================================================

async function runScan(generateReport: boolean): Promise<ScanResult | undefined> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        vscode.window.showErrorMessage('No workspace folder open');
        return undefined;
    }

    const config = vscode.workspace.getConfiguration('rustcola');
    const binaryPath = config.get<string>('binaryPath') || 'cargo-cola';
    const outputDir = config.get<string>('outputDirectory') || 'out/cola';

    const outputPath = path.join(workspaceFolder.uri.fsPath, outputDir);
    const llmReportPath = generateReport 
        ? path.join(outputPath, 'security-analysis.md')
        : undefined;

    const args = [
        '--crate-path', workspaceFolder.uri.fsPath,
        '--out-dir', outputPath,
    ];

    if (llmReportPath) {
        args.push('--llm-report', llmReportPath);
    }

    return vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Rust-cola: Scanning...',
        cancellable: true
    }, async (progress, token) => {
        return new Promise<ScanResult | undefined>((resolve, reject) => {
            const process = cp.spawn(binaryPath, args, {
                cwd: workspaceFolder.uri.fsPath
            });

            let stdout = '';
            let stderr = '';

            process.stdout?.on('data', (data) => {
                stdout += data.toString();
            });

            process.stderr?.on('data', (data) => {
                stderr += data.toString();
            });

            process.on('close', (code) => {
                if (code === 0 || code === 1) { // 1 = findings found, still success
                    const findingsPath = path.join(outputPath, 'findings.json');
                    try {
                        const findingsJson = fs.readFileSync(findingsPath, 'utf-8');
                        const findings = JSON.parse(findingsJson);
                        
                        const result: ScanResult = {
                            findings,
                            findingsPath,
                            sarifPath: path.join(outputPath, 'cola.sarif'),
                            llmReportPath,
                            findingsCount: findings.length
                        };

                        vscode.window.showInformationMessage(
                            `Rust-cola scan complete: ${findings.length} findings`
                        );

                        resolve(result);
                    } catch (e) {
                        reject(new Error(`Failed to parse findings: ${e}`));
                    }
                } else {
                    reject(new Error(`Scan failed with code ${code}: ${stderr}`));
                }
            });

            token.onCancellationRequested(() => {
                process.kill();
                resolve(undefined);
            });
        });
    });
}

// ============================================================================
// Chat Participant Handler
// ============================================================================

interface ScanResult {
    findings: any[];
    findingsPath: string;
    sarifPath: string;
    llmReportPath?: string;
    findingsCount: number;
}

async function handleChatRequest(
    request: vscode.ChatRequest,
    context: vscode.ChatContext,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    
    const command = request.command;

    if (command === 'scan') {
        return handleScanCommand(request, stream, token);
    } else if (command === 'analyze') {
        return handleAnalyzeCommand(request, stream, token);
    } else if (command === 'explain') {
        return handleExplainCommand(request, stream, token);
    } else {
        // Default: treat as general question about rust-cola
        return handleGeneralQuestion(request, stream, token);
    }
}

async function handleScanCommand(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    stream.markdown('🔍 **Starting Rust-cola security scan...**\n\n');
    
    try {
        const result = await runScan(true);
        
        if (!result) {
            stream.markdown('Scan was cancelled.\n');
            return { metadata: { command: 'scan', status: 'cancelled' } };
        }

        stream.markdown(`✅ **Scan complete!** Found ${result.findingsCount} findings.\n\n`);
        
        if (result.llmReportPath && fs.existsSync(result.llmReportPath)) {
            stream.markdown('📊 **Generated LLM analysis context.** I will now analyze the findings...\n\n');
            
            const reportContent = fs.readFileSync(result.llmReportPath, 'utf-8');
            
            // The LLM will automatically process this and generate a report
            stream.markdown('---\n\n');
            stream.markdown('Based on the scan results, here is my security analysis:\n\n');
            
            // Include the findings context for Claude to analyze
            // The actual analysis will be done by Claude based on the prompt in the report
            stream.markdown(`<details><summary>Raw findings context (${result.findingsCount} findings)</summary>\n\n`);
            stream.markdown('```\n');
            stream.markdown(reportContent.substring(0, 10000)); // Truncate if too long
            if (reportContent.length > 10000) {
                stream.markdown('\n... (truncated, see full report)\n');
            }
            stream.markdown('```\n</details>\n\n');
        }

        return { 
            metadata: { 
                command: 'scan', 
                status: 'success',
                findingsCount: result.findingsCount 
            } 
        };
    } catch (e) {
        stream.markdown(`❌ **Scan failed:** ${e}\n`);
        return { metadata: { command: 'scan', status: 'error' } };
    }
}

async function handleAnalyzeCommand(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        stream.markdown('No workspace folder open.\n');
        return { metadata: { command: 'analyze', status: 'error' } };
    }

    const config = vscode.workspace.getConfiguration('rustcola');
    const outputDir = config.get<string>('outputDirectory') || 'out/cola';
    const findingsPath = path.join(workspaceFolder.uri.fsPath, outputDir, 'findings.json');

    if (!fs.existsSync(findingsPath)) {
        stream.markdown('No scan results found. Run `@rustcola /scan` first.\n');
        return { metadata: { command: 'analyze', status: 'no-results' } };
    }

    stream.markdown('📊 **Analyzing existing scan results...**\n\n');
    
    const findingsJson = fs.readFileSync(findingsPath, 'utf-8');
    const findings = JSON.parse(findingsJson);
    
    stream.markdown(`Found ${findings.length} findings to analyze.\n\n`);
    stream.markdown('I will now produce a security report. Please see the analysis below:\n\n');
    
    // The chat model will analyze the findings based on the context
    return { metadata: { command: 'analyze', status: 'success' } };
}

async function handleExplainCommand(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    const query = request.prompt;
    
    stream.markdown(`📖 **Explaining:** ${query}\n\n`);
    
    // Claude will explain based on the rule ID or concept mentioned
    return { metadata: { command: 'explain', status: 'success' } };
}

async function handleGeneralQuestion(
    request: vscode.ChatRequest,
    stream: vscode.ChatResponseStream,
    token: vscode.CancellationToken
): Promise<vscode.ChatResult> {
    stream.markdown('I am the Rust-cola security analyzer. I can help you:\n\n');
    stream.markdown('- `/scan` - Run a security scan on your Rust project\n');
    stream.markdown('- `/analyze` - Analyze existing scan results\n');
    stream.markdown('- `/explain <rule>` - Explain a specific security rule\n\n');
    stream.markdown('What would you like to do?\n');
    
    return { metadata: { command: 'help' } };
}

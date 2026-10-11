import React, { useState, useEffect } from 'react';
import { FileCode, Copy, Check, Download, FolderGit2, Terminal, ExternalLink } from 'lucide-react';
import JSZip from 'jszip';

interface CodeExplorerProps {
  initialFiles?: Record<string, string>;
}

export const CodeExplorer: React.FC<CodeExplorerProps> = () => {
  const [files, setFiles] = useState<Record<string, string>>({});
  const [selectedFile, setSelectedFile] = useState<string>('main.py');
  const [copied, setCopied] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch('/api/python-sources')
      .then((res) => res.json())
      .then((data) => {
        if (data && data.files) {
          setFiles(data.files);
        }
        setIsLoading(false);
      })
      .catch((err) => {
        console.warn('Failed to load python sources from API:', err);
        setIsLoading(false);
      });
  }, []);

  const handleCopy = () => {
    const content = files[selectedFile] || '';
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadZip = async () => {
    const zip = new JSZip();
    for (const [name, content] of Object.entries(files)) {
      zip.file(name, content);
    }
    const blob = await zip.generateAsync({ type: 'blob' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'multimodal-phishing-detection-framework.zip';
    a.click();
    URL.revokeObjectURL(url);
  };

  const fileList = Object.keys(files);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
      {/* Header bar */}
      <div className="bg-slate-950 px-5 py-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
            <FolderGit2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-bold text-slate-100 flex items-center gap-2">
              Python Deliverables & Source Code Repository
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                Production-Ready
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Complete source code generated for FastAPI, Streamlit, Celery, Whisper, OpenCV, Librosa, and LLM Orchestrator.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer border border-slate-700"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied!' : 'Copy File'}
          </button>

          <button
            onClick={handleDownloadZip}
            className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-mono transition flex items-center gap-1.5 cursor-pointer shadow"
          >
            <Download className="w-3.5 h-3.5" />
            Download Entire Repo (.ZIP)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4">
        {/* File Sidebar */}
        <div className="bg-slate-950/70 border-r border-slate-800 p-3 space-y-1">
          <div className="text-[11px] font-mono text-slate-400 px-2.5 py-1 uppercase tracking-wider">
            Repository Files
          </div>
          {fileList.map((filename) => {
            const isSelected = selectedFile === filename;
            return (
              <button
                key={filename}
                onClick={() => setSelectedFile(filename)}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono flex items-center justify-between transition cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600/20 border border-blue-500/40 text-blue-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <span className="flex items-center gap-2 truncate">
                  <FileCode className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-blue-400' : 'text-slate-500'}`} />
                  {filename}
                </span>
                {filename === 'main.py' && (
                  <span className="text-[9px] px-1 rounded bg-blue-500/20 text-blue-300">FastAPI</span>
                )}
                {filename === 'app.py' && (
                  <span className="text-[9px] px-1 rounded bg-red-500/20 text-red-300">Streamlit</span>
                )}
                {filename === 'extractors.py' && (
                  <span className="text-[9px] px-1 rounded bg-purple-500/20 text-purple-300">Pipeline</span>
                )}
                {filename === 'analyzer.py' && (
                  <span className="text-[9px] px-1 rounded bg-emerald-500/20 text-emerald-300">LLM Engine</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Code View Area */}
        <div className="md:col-span-3 bg-slate-950 p-4 overflow-x-auto max-h-[640px] flex flex-col">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800/80 text-xs font-mono text-slate-400">
            <span>FILE: {selectedFile}</span>
            <span>Lines: {(files[selectedFile] || '').split('\n').length}</span>
          </div>

          <pre className="font-mono text-xs text-slate-300 leading-relaxed overflow-auto flex-1 selection:bg-blue-600/30">
            <code>
              {files[selectedFile] || (isLoading ? '# Loading repository sources...' : '# File not found')}
            </code>
          </pre>
        </div>
      </div>
    </div>
  );
};

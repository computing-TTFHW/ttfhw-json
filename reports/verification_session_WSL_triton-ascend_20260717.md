# 验证会话记录 - triton-ascend

## 基本信息
- **仓库**: https://github.com/triton-lang/triton-ascend
- **验证时间**: 2026-07-17
- **验证环境**: WSL Docker (Ubuntu 24.04)
- **机器规格**: Intel Xeon Gold 6266C @ 3.00GHz, 8核, 15Gi内存, x86_64

## 步骤1：文档阅读

### 仓库概述
Triton-Ascend 是针对华为昇腾(Ascend)平台适配的 Triton 编译框架，使 Triton 代码能够在 Ascend NPU 硬件上高效运行。

### 关键信息提取

**架构要求**: linux(aarch64/x86_64) — 来自 `docs/en/quick_start.md`

**镜像选择**: Dockerfile FROM `quay.io/ascend/cann:8.5.0-a3-ubuntu22.04-py3.10`（Ubuntu基础）→ 选择 Ubuntu 24.04

**构建依赖**:
- 系统: zlib1g-dev, clang-15, lld-15, ccache, cmake, ninja-build, make, git
- Python构建: ninja, cmake, wheel, pybind11, nanobind
- Python运行: torch-npu==2.7.1.post4, numpy==1.26.4, scipy, pytest等

**构建命令**: `pip install -e .`（在线源码编译安装）

**测试命令**:
- `make test-lit` — LIT编译器测试（不需要NPU硬件）
- `make test-cpp` — C++单元测试（默认未构建）
- `make test-unit` — Python单元测试（需要NPU硬件）
- `make test-nogpu` — 不需要GPU的测试

**样例命令**: `python3 ./third_party/ascend/tutorials/01-vector-add.py`

**特殊依赖**:
- CANN Community Edition 9.0.0 — 从 https://www.hiascend.com/cann/download 下载（需注册）
- torch-npu 2.7.1.post4 — 从 PyPI 安装
- LLVM预编译包 — 构建时自动从华为OBS下载

## 步骤2：验证执行

### 容器启动
- 镜像: ubuntu:24.04
- 容器名: ttfhw-triton-ascend-env
- 命令: `docker run -d --name ttfhw-triton-ascend-env -v ./tmp_src/triton-ascend:/workspace -w /workspace ubuntu:24.04 tail -f /dev/null`

### 依赖安装
1. **系统依赖**: `apt-get install -y zlib1g-dev clang-15 lld-15 ccache cmake ninja-build make git python3 python3-pip python3-dev`
2. **clang/lld替代项**: `update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100`
3. **pip镜像**: 配置清华源
4. **Python构建依赖**: `pip install --break-system-packages ninja cmake wheel pybind11 nanobind`
5. **开发依赖**: `pip install --break-system-packages -r requirements_dev.txt`

### 构建执行
- **命令**: `MAX_JOBS=4 TRITON_BUILD_WITH_CCACHE=false pip install --break-system-packages --no-build-isolation -e .`
- **结果**: 成功
- **耗时**: 27分59秒 (1679秒)
- **产物**: libtriton.so (173M), libentryC.so (237K), triton-opt (146M), triton-mlir-opt (184M)

### 构建后修复
editable安装(pip install -e .)未正确覆盖PyPI triton包，手动执行：
1. 创建后端符号链接: `ln -sf /workspace/third_party/ascend/backend /usr/local/lib/python3.12/dist-packages/triton/backends/ascend`
2. 复制编译的.so文件: `cp /workspace/python/triton/_C/libtriton.so /usr/local/lib/python3.12/dist-packages/triton/_C/`
3. 同步源码树Python文件到安装位置

修复后导入成功: `from triton.backends.ascend.compiler import AscendBackend` ✓

### 单元测试

#### LIT编译器测试
- **命令**: `ninja check-triton-lit-tests`
- **结果**: 213个测试，211通过，2失败 (99.06%)
- **耗时**: 3.14秒
- **失败项**:
  1. `TRITON :: Triton/canonicalize.mlir` — FileCheck模式匹配失败
  2. `TRITON :: TritonGPU/amd/amd-canonicalize-pointers.mlir` — FileCheck模式匹配失败

#### Python前端测试
- **命令**: `pytest python/test/unit/language/test_frontend.py`
- **结果**: 31个测试全部通过
- **耗时**: 2.3秒

#### Gluon前端测试
- **命令**: `pytest python/test/gluon/test_frontend.py`
- **结果**: 1个失败 (test_convert_layout API参数类型不匹配)
- **耗时**: 0.82秒

### 样例执行
- **命令**: `python3 ./third_party/ascend/tutorials/01-vector-add.py`
- **结果**: 失败
- **耗时**: 2.86秒
- **错误**: `ImportError: libhccl.so: cannot open shared object file` — CANN包未安装

### 清理
- `docker stop ttfhw-triton-ascend-env && docker rm ttfhw-triton-ascend-env`

## 步骤3：验证总结

### 最终结果

| 项目 | 状态 | 详情 |
|------|------|------|
| 构建 | 成功 | 耗时1679秒，产出libtriton.so等8个构建产物 |
| LIT测试 | 部分成功 | 211/213通过(99.06%)，2个FileCheck匹配失败 |
| Python前端测试 | 成功 | 31/31通过 |
| Gluon前端测试 | 部分失败 | 1个API参数类型不匹配失败 |
| 样例运行 | 失败 | 缺少CANN运行时库(无Ascend NPU硬件) |

### 文档缺失
1. CANN下载链接需注册登录，未提供直接URL
2. editable安装覆盖问题在FAQ中有记录但安装步骤未提及
3. C++单元测试默认不构建未明确说明
4. Python单元测试硬件要求未在测试章节标注
5. requirements.txt中torch-npu版本号与安装指南不一致

### 验证结论
Triton-Ascend 仓库在 Ubuntu 24.04 容器中能够成功完成源码编译构建。编译器层面的LIT测试通过率99.06%，Python前端测试全部通过。样例运行和Python单元测试需要CANN运行时环境和Ascend NPU硬件支持，在无NPU硬件的容器环境中无法执行，这是硬件依赖导致的预期限制而非代码问题。

# SSPWorkers 客户端

一个基于 .NET 10.0 的 Windows Forms 应用程序，用于管理和配置 SSPWorkers 服务。

## 主要功能

- **服务管理**: 启动、停止和管理 SSPWorkers 服务进程
- **配置管理**: 图形化界面配置服务器、代理和路由设置
- **系统托盘**: 最小化到系统托盘，支持托盘菜单操作
- **开机自启**: 支持开机自动启动功能
- **路由模式**: 支持全局模式、绕过中国大陆等多种路由规则
- **进程监控**: 实时监控服务进程状态，异常退出自动重启

## 开发环境要求

- .NET 10.0 SDK，低版本没有尝试过
- Visual Studio 2022 或更高版本，开发时使用Visual Studio 2026
- Windows 操作系统，必须支持PowerShell命令

## 如何打开项目

### 方法1：使用 Visual Studio
1. 双击 `SSPWorkersGUI.slnx` 文件
2. Visual Studio 会自动加载项目

### 方法2：使用 Visual Studio Code
1. 安装 C# Dev Kit 扩展
2. 打开项目根目录
3. VS Code 会检测到项目并提示打开

### 方法3：使用命令行
```bash
# 克隆项目后
cd SSPWorkersGUI
dotnet build
dotnet run
```

## 项目结构

```
SSPWorkersGUI/
├── SSPWorkersGUI.slnx     # Visual Studio 解决方案文件
├── build.txt               # 构建命令参考文档
├── README.md               # 项目说明文档
├── .gitignore              # Git忽略文件配置
├── SSPWorkersGUI/          # 主项目目录
│   ├── SSPWorkersGUI.csproj # 项目文件
│   ├── Program.cs          # 程序入口点
│   ├── App.cs              # 主窗体代码（包含核心业务逻辑）
│   ├── App.Designer.cs     # 窗体设计器代码
│   ├── App.resx            # 窗体资源文件
│   ├── app.ico             # 应用程序图标
│   ├── Properties/         # 项目属性
│   │   ├── PublishProfiles/
│   │   ├── Resources.Designer.cs
│   │   └── Resources.resx
│   ├── bin/                # 编译输出目录
│   └── obj/                # 编译中间文件目录
```

## 构建项目

### 开发环境
```bash
# 标准构建
dotnet build

# 指定项目构建
dotnet build SSPWorkersGUI/SSPWorkersGUI.csproj

# 快速构建（最少输出）
dotnet build SSPWorkersGUI/SSPWorkersGUI.csproj --verbosity minimal

# 快速构建（跳过恢复）
dotnet build --verbosity minimal --no-restore
dotnet build SSPWorkersGUI/SSPWorkersGUI.csproj --verbosity minimal --no-restore
```

### 发布版本

可以使用Visual Studio来生成，或者下面的命令。

#### 依赖运行时发布（需要系统安装.NET 10.0）
```bash
dotnet publish -c Release -r win-x64 --no-self-contained -p:PublishSingleFile=true
```

#### 自包含单文件发布（免安装，约116MB）
```bash
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true
```

> 💡 **提示**: 更多构建命令请参考 `build.txt` 文件

## 运行项目

### 开发环境运行
```bash
# 在项目根目录下
dotnet run --project SSPWorkersGUI/SSPWorkersGUI.csproj
```

### 直接运行可执行文件
1. 确保有 `SSP-workers.exe`、`core.exe` 或 `cli.exe` 中任意一个程序名在输出目录中（都是同一个程序，名称不同）
2. 运行编译后的程序：
   ```bash
   cd SSPWorkersGUI\bin\Debug\net10.0-windows
   "SSPWorkers Client.exe"
   ```

### 可执行文件优先级
程序会按以下优先级查找可执行文件：
1. `core.exe`
2. `cli.exe` 
3. `SSP-workers.exe`

## 配置文件

程序会在首次运行时自动创建配置文件：
- 位置：`C:\Users\<user>\AppData\Roaming\SSP Workers\config.json`

  示例："C:\Users\Administrator\AppData\Roaming\SSP Workers\config.json"

- 包含服务器配置、代理设置等

## 注意事项

- 项目使用 .NET 10.0，需要相应的 SDK
- 需要搭配 core.exe 、 ssp.exe 、ssp-core.exe 中任意一个程序名使用
- 程序支持 unsafe 代码块，用于进程管理
- 配置文件自动保存在Windows中的用户/AppData/Roaming/SSP Workers/config.json目录下，也可将配置文件放在同一目录下

## .NET 8.0 兼容性

如果需要在 .NET 8.0 环境下运行，请按以下步骤修改：

1. 修改 `SSPWorkersGUI/SSPWorkersGUI.csproj`：
   ```xml
   <TargetFramework>net8.0-windows</TargetFramework>
   ```

2. 注释掉 `SSPWorkersGUI/App.Designer.cs` 中的：
   ```csharp
   process1.StartInfo.CreateNewProcessGroup = false;
   ```

3. 使用相应的发布命令：
   ```bash
   # .NET 8.0 依赖版本
   dotnet publish -c Release -r win-x64 --no-self-contained -p:PublishSingleFile=true
   
   # .NET 8.0 自包含版本
   dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true
   ```

4. 下载并安装 .NET Desktop Runtime 8.0.xx

## 技术栈

- **框架**: .NET 10.0 Windows Forms
- **语言**: C# 10.0+
- **UI**: Windows Forms 原生控件
- **配置**: JSON 格式配置文件
- **进程管理**: System.Diagnostics.Process
- **网络**: System.Net.Sockets


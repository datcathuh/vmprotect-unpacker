


# credits

- deepseek - helped me actually understand the vmprotect source and write most of the unpack logic
- [StormingMoon/VMProtectUnpacker](https://github.com/StormingMoon/VMProtectUnpacker) - [inspired me & took some code from his base]
- vmprotect 3.5.1 source - https://0xacab.org/bidasci/vmprotect-3.5.1

# notes
THIS ISNT CLOSE TO DONE GOT SOME MAYOR BUGS BE AWARE

tested / developed on vmprotect v 3.8.4
u might get flagged for debugger but it still dumps / unpacks from what i noticed.

also the import rebuilding is kinda scuffed sometimes, dumped exe might crash. brute-force scan doesnt always find all the iat slots. if u wanna fix it go ahead idk will look into it in the future.
note the project at this current state is not finished / got some issues i am working on fixing / resolving them!

# before

![non packed](assets/nopack.png)

non packed pseudo
```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  MessageBoxW(hWnd: nullptr, lpText: L"Hello, world!", lpCaption: L"My Message Box", uType: 0x40u);
  return 0;
}
```

# after

![unpacked dump](assets/unpacked.png)

unpacked pseudo
```c
__int64 sub_140001000()
{
  ((void (__fastcall *)(_QWORD, const wchar_t *, const wchar_t *, __int64))qword_140183240[0])(
    a1: 0,
    a2: L"Hello, world!",
    a3: L"My Message Box",
    a4: 64);
  return 0;
}
```



# Legal / Intended Use

This project is intended for security research, reverse-engineering education, and analysis of software that you are legally authorized to analyze.

Only use this software with binaries, software, and systems that you own or have explicit permission to analyze. Do not use it to circumvent licensing restrictions, access controls, or other protections on software without authorization.

This project is not affiliated with or endorsed by VMProtect or its developers.

You are responsible for ensuring that your use of this software complies with applicable laws, licenses, and agreements.

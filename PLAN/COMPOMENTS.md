المكون                        اللغة        الحجم        القرار
─────────────────────────────────────────────────────────────
Decompiler engine             C++          ~150K سطر    خذه كما هو
Sleigh compiler               C++          ~30K سطر     خذه كما هو
SoftwareModeling              Java         ~200K سطر    ترجم
Generic/Utility               Java         ~100K سطر    ترجم
Loader (ELF/PE/Mach-O)        Java         ~80K سطر     استبدل بـ LIEF
Disassembler bridge           Java         ~40K سطر     استبدل بـ Capstone
UI (Swing)                    Java         ~300K سطر    استبدل بـ Qt
Plugin system                 Java         ~50K سطر     اكتب من صفر
Database layer                Java         ~60K سطر     استبدل بـ SQLite


// we use all the EXIST main components that we can use Directly, we just elemenate "Java".
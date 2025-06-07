import pefile
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
import os
import gdb

def get_pe_section_offsets(file_path):
    """
    解析PE文件，返回.text和.data节的文件偏移（PointerToRawData）。
    :param file_path: PE文件路径
    :return: dict，包含.text和.data节的偏移，未找到则为None
    """
    pe = pefile.PE(file_path)
    offsets = {'.text': None, '.data': None}
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').rstrip('\x00')
        if name == '.text':
            offsets['.text'] = section.PointerToRawData
        elif name == '.data':
            offsets['.data'] = section.PointerToRawData
    return offsets

def get_elf_section_offsets(file_path):
    """
    解析ELF文件，返回.text和.data节的文件偏移（sh_offset）。
    :param file_path: ELF文件路径
    :return: dict，包含.text和.data节的偏移，未找到则为None
    """
    offsets = {'.text': None, '.data': None}
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        for idx in range(elf.num_sections()):
            try:
                section = elf.get_section(idx)
                if section is None:
                    continue
                name = section.name
                # print(f"Section {idx}: {name}, offset={hex(section['sh_offset'])}")
                if name == '.text':
                    offsets['.text'] = section['sh_offset']
                elif name == '.data':
                    offsets['.data'] = section['sh_offset']
            except ELFError:
                continue
    return offsets

def get_section_offsets_in_folder(folder_path):
    """
    遍历指定文件夹下所有文件，获取每个文件的.text和.data节偏移。
    如果有同名（仅扩展名不同）的文件，只解析一个（优先PE文件）。
    :param folder_path: 文件夹路径
    :return: dict，key为文件名，value为偏移dict
    """
    results = {}
    seen_basenames = set()
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if not os.path.isfile(file_path):
            continue
        base, ext = os.path.splitext(filename)
        ext = ext.lower()
        if base in seen_basenames:
            continue
        if ext == '.efi':
            offsets = get_pe_section_offsets(file_path)
            results[filename] = offsets
            seen_basenames.add(base)
        elif ext == '.debug':
            if not os.path.exists(os.path.join(folder_path, base + '.efi')):
                offsets = get_elf_section_offsets(file_path)
                results[filename] = offsets
                seen_basenames.add(base)
    return results

def generate_gdb_symbol_cmd(module_path, load_addr):
    """
    生成gdb add-symbol-file命令，自动根据文件后缀选择elf或pe解析
    :param module_path: 符号文件路径（.debug或.efi）
    :param load_addr: 加载基址
    :return: gdb命令字符串
    """
    ext = os.path.splitext(module_path)[1].lower()
    if ext == ".debug":
        offsets = get_elf_section_offsets(module_path)
    elif ext == ".efi":
        offsets = get_pe_section_offsets(module_path)
    else:
        raise ValueError(f"不支持的文件类型: {module_path}")
    text_offset, data_offset = offsets['.text'], offsets['.data']
    symbol_cmd = (
        f'add-symbol-file {module_path} '
        f'{hex(load_addr + text_offset) if text_offset is not None else "0"} '
        f'-s .data {hex(load_addr + data_offset) if data_offset is not None else "0"}'
    )
    return symbol_cmd

class ModuleLoadBreakPoint(gdb.Breakpoint):
    """
    在PeCoffLoaderRelocateImageExtraAction设置断点，自动加载符号。
    """
    def __init__(self, symbol_folder):
        super().__init__("PeCoffLoaderRelocateImageExtraAction", gdb.BP_BREAKPOINT, internal=False)
        self.symbol_folder = symbol_folder

    def stop(self):
        # 获取ImageContext参数
        image_context_ptr = int(gdb.parse_and_eval("ImageContext"))
        image_address = int(gdb.parse_and_eval("((PE_COFF_LOADER_IMAGE_CONTEXT*)%#x)->ImageAddress" % image_context_ptr))

        # 读取PdbPointer字段（假设偏移正确，类型为char*）
        pdb_pointer = gdb.parse_and_eval("((PE_COFF_LOADER_IMAGE_CONTEXT*)%#x)->PdbPointer" % image_context_ptr)
        pdb_path = pdb_pointer.string() if pdb_pointer else None

        # 只查找ELF文件路径
        if pdb_path:
            pdb_dir = os.path.dirname(pdb_path)
            base_name = os.path.splitext(os.path.basename(pdb_path))[0]
            elf_path = os.path.normpath(os.path.join(pdb_dir, base_name + ".debug"))
            if os.path.exists(elf_path):
                gdb_cmd = generate_gdb_symbol_cmd(elf_path, image_address)
                try:
                    gdb.execute(gdb_cmd)
                    print(f"[ModuleLoadBreakPoint] 加载符号: {gdb_cmd}")
                except Exception as e:
                    print(f"[ModuleLoadBreakPoint] gdb.execute异常: {e}")
            else:
                print(f"[ModuleLoadBreakPoint] 未找到ELF文件: {elf_path}")
        else:
            print("[ModuleLoadBreakPoint] 未获取到PdbPointer")
        return False  # 不中断

# 示例用法
if __name__ == "__main__":
    # file_path = "DxeCore.efi"
    # offsets = get_pe_section_offsets(file_path)
    # print(offsets)
    # print(f".text 节偏移: {hex(offsets['.text']) if offsets['.text'] is not None else None}")
    # print(f".data 节偏移: {hex(offsets['.data']) if offsets['.data'] is not None else None}")

    # # ELF文件测试
    # elf_file_path = "DxeCore.debug"
    # elf_offsets = get_elf_section_offsets(elf_file_path)
    # print(elf_offsets)
    # print(f"ELF .text 节偏移: {hex(elf_offsets['.text']) if elf_offsets['.text'] is not None else None}")
    # print(f"ELF .data 节偏移: {hex(elf_offsets['.data']) if elf_offsets['.data'] is not None else None}")

    # # 文件夹测试，结果写入文件
    # folder_path = r"\\wsl.localhost\Ubuntu-20.04\home\xp\Build\ArmVirtQemu-AARCH64\DEBUG_GCC5\AARCH64"
    # all_offsets = get_section_offsets_in_folder(folder_path)
    # with open("section_offsets.txt", "w", encoding="utf-8") as f:
    #     for filename, offsets in all_offsets.items():
    #         f.write(f"{filename}: {offsets}\n")
    #         f.write(f"  .text 节偏移: {hex(offsets['.text']) if offsets['.text'] is not None else None}\n")
    #         f.write(f"  .data 节偏移: {hex(offsets['.data']) if offsets['.data'] is not None else None}\n")

    # # 生成gdb调试脚本命令示例
    # module_path = "DxeCore.debug"
    # load_addr = 0x400000  # 示例基址
    # gdb_cmd = generate_gdb_symbol_cmd(module_path, load_addr)
    # print("GDB add-symbol-file 命令：")
    # print(gdb_cmd)

    # # 生成gdb调试脚本命令示例
    # module_path = "DxeCore.efi"
    # load_addr = 0x400000  # 示例基址
    # gdb_cmd = generate_gdb_symbol_cmd(module_path, load_addr)
    # print("GDB add-symbol-file 命令：")
    # print(gdb_cmd)

    # 设置模块加载断点示例
    ModuleLoadBreakPoint("/home/xp/Opensource/edk2/Build/ArmVirtQemu-AARCH64/DEBUG_GCC5/AARCH64")
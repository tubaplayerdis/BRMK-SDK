#include "../../Include/Hooking/Signature.hpp"

#include <windows.h>
#include <chrono>
#include <libloaderapi.h>
#include <map>
#include <utility>
#include <psapi.h>
#include <processthreadsapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <iostream>
#pragma comment(lib, "Psapi.lib")

namespace
{
	static std::unique_ptr<std::map<std::string, unsigned long long>> Cache;

	static unsigned long long FindPatternF(const char* pattern, const char* mask, unsigned long long base, std::uint64_t size)
	{
		const std::uint64_t patternLen = strlen(mask);
		if (patternLen == 0 || size < patternLen) {
			return 0;
		}

		// 1. Create the bad-character skip table
		std::vector<std::uint64_t> skipTable(256, patternLen);
		for (std::uint64_t i = 0; i < patternLen - 1; ++i) {
			if (mask[i] != '?') {
				skipTable[static_cast<unsigned char>(pattern[i])] = patternLen - 1 - i;
			}
		}

		const unsigned long long searchEnd = base + size - patternLen;
		unsigned long long currentPos = base;

		while (currentPos <= searchEnd) {
			// 2. Compare from the end of the pattern backwards
			bool match = true;
			for (int j = patternLen - 1; j >= 0; --j) {
				if (mask[j] != '?' && pattern[j] != *(char*)(currentPos + j)) {
					// 3. On mismatch, use the skip table to jump forward
					// The character from the memory text determines the jump distance.
					const unsigned char mismatched_char = *(unsigned char*)(currentPos + patternLen - 1);
					currentPos += skipTable[mismatched_char];
					match = false;
					break;
				}
			}

			if (match) {
				return currentPos; // Found it
			}
		}

		return 0; // Not found
	}

	static unsigned long long FindPatternS(const char* pattern, const char* mask, unsigned long long base, std::uint64_t size)
	{
		std::uint64_t patternLen = strlen(mask);

		// Failsafe: invalid pattern or module too small to contain it
		if (patternLen == 0 || size < patternLen) {
			return 0;
		}

		const std::uint64_t searchRange = size - patternLen;

		for (std::uint64_t i = 0; i <= searchRange; i++) {
			bool found = true;

			for (std::uint64_t j = 0; j < patternLen; j++) {
				if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
					found = false;
					break;
				}
			}

			if (found)
				return base + i;
		}

		return 0;
	}

	static bool GetSectionByName(const char* name, unsigned long long& base, std::uint64_t& size, const char* moduleName = nullptr)
	{
		HMODULE hModule = GetModuleHandleA(moduleName);
		if (!hModule) return false;

		uintptr_t moduleBase = (uintptr_t)hModule;
		auto dos = (PIMAGE_DOS_HEADER)moduleBase;
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt = (PIMAGE_NT_HEADERS)(moduleBase + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

		auto section = IMAGE_FIRST_SECTION(nt);
		for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (strncmp((char*)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
			{
				base = moduleBase + section->VirtualAddress;
				size = section->Misc.VirtualSize;
				return true;
			}
		}

		return false;
	}

	static void SignatureToPatternAndMask(const std::string& sig_str, std::vector<char>& pattern, std::string& mask) {
		pattern.clear();
		mask.clear();

		std::stringstream ss(sig_str);
		std::string token;

		while (ss >> token) {
			if (token == "??") {
				// For wildcards, use any value (0x00) in pattern, '?' in mask
				pattern.push_back(0x00);
				mask += '?';
			}
			else {
				// Convert hex string to byte value
				if (token.length() == 2) {
					char value = static_cast<char>(std::stoi(token, nullptr, 16));
					pattern.push_back(value);
					mask += 'x';
				}
			}
		}

		// Ensure null termination for C-style strings
		pattern.push_back(0x00);
	}

	static std::pair<const char*, const char*> ConvertSignature(const std::string& signature) {
		static std::vector<char> pattern;
		static std::string mask;

		SignatureToPatternAndMask(signature, pattern, mask);

		return { pattern.data(), mask.c_str() };
	}

	std::uintptr_t ResolveCallTarget(std::uintptr_t callInstructionAddress)
	{
		// callInstructionAddress points at the 0xE8 byte itself
		std::int32_t displacement;
		std::memcpy(&displacement, reinterpret_cast<void*>(callInstructionAddress + 1), sizeof(displacement));

		std::uintptr_t nextInstruction = callInstructionAddress + 5; // E8 + 4 bytes
		return nextInstruction + displacement;
	}

	unsigned long long FindPatternF(const char* pattern, const char* mask)
	{
		unsigned long long base = (unsigned long long)GetModuleHandle(NULL);
		MODULEINFO info = {};
		GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &info, sizeof(info));
		unsigned __int64 size = (unsigned __int64)info.SizeOfImage;
		unsigned __int64 patternLen = strlen(mask);

		for (unsigned __int64 i = 0; i < size - patternLen; i++) {
			bool found = true;

			for (unsigned __int64 j = 0; j < patternLen; j++) {
				if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
					found = false;
					break;
				}
			}

			if (found)
				return base + i;
		}

		return 0;
	}
}

Signature::Signature(const char* signature) noexcept : Sig(signature)
{
	InternalResolveSignature(Sig, TEXT);
}

Signature::Signature(const char* signature, const char* module, bool call_target) noexcept : Sig(signature)
{
	if (!Cache)
	{
		Cache = std::make_unique<std::map<std::string, unsigned long long>>();
	}

	InternalResolveSignature(Sig, TEXT, module, call_target);
}

Signature::Signature(std::uintptr_t address) noexcept : Sig(std::to_string(address))
{
	if (!Cache)
	{
		Cache = std::make_unique<std::map<std::string, unsigned long long>>();
	}

	Cache->insert(std::make_pair(Sig, address));
}

std::uintptr_t Signature::GetPtr() const
{
	return InternalResolveSignature(Sig, TEXT);
}

std::string Signature::GetSig() const
{
	return Sig;
}


/// Resolve a signature to an address. Uses the format: "48 89 7C 24 ?? 41 56 48 83 EC ?? 48 8B FA 4C 8B F1 E8 ?? ?? ?? ??"
/// @param signature signature to resolve
/// @return address of the function representing the signature. 0 if not found.
uintptr_t Signature::InternalResolveSignature(const std::string& signature, SearchContext context, const char* Module, bool call_target) noexcept
{
	if (!Cache)
	{
		Cache = std::make_unique<std::map<std::string, unsigned long long>>();
	}

	if (Cache->contains(std::string(signature)))
	{
		return Cache->at(std::string(signature));
	}

	unsigned long long addr = 0;
	auto [pattern, mask] = ConvertSignature(signature);

	auto SearchSection = [](const char* section, const char* pattern, const char* mask, const char* module = nullptr) -> unsigned long long
	{
		std::uintptr_t base = 0; std::uint64_t size = 0;
		if (!GetSectionByName(section,base, size, module)) return 0;

		unsigned long long addr = FindPatternF(pattern, mask, base, size);
		if (addr == 0) {
			addr = FindPatternS(pattern, mask, base, size);
		}

		return addr;
	};

	if (!addr && context & TEXT)
	{
		addr = SearchSection(".text", pattern, mask, Module);
	}

	if (!addr && context & DATA)
	{
		addr = SearchSection(".data", pattern, mask, Module);
	}

	if (!addr && context & RDATA)
	{
		addr = SearchSection(".rdata", pattern, mask, Module);
	}

	if (!addr && context & BSS)
	{
		addr = SearchSection(".bss", pattern, mask, Module);
	}

	if (call_target && addr)
	{
		addr = ResolveCallTarget(addr);
	}

	if (addr != 0)
	{
		Cache->insert(std::make_pair(std::string(signature), addr));
	}

	if (addr == 0)
	{
		std::cerr << "SIGNATURE NOT FOUND: " << std::string(signature) << std::endl;
	}

	return addr;
}

//Signature UBRICK_GETFUELLEVEL("40 53 48 83 EC ?? 48 8B 01 48 8B D9 FF 90 ?? ?? ?? ?? 48 8B C8 48 85 C0 75 ??");

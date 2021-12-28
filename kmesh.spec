%global debug_package %{nil}

Name:          kmesh
Version:       1.0.0
Release:       1
Summary:       %{name} is a eBPF-based service mesh kernel solution
License:       Mulan PSL v2
URL:           https://gitee.com/openeuler
Source0:       %{name}-%{version}.tar.gz

BuildRequires: clang llvm
BuildRequires: libbpf-devel 
BuildRequires: kernel-devel >= 5.10
BuildRequires: golang >= 1.16

Requires: libbpf bpftool

%description
%{name} is a eBPF-based service mesh kernel solution.

ExclusiveArch: x86_64 aarch64

%prep
%autosetup -n %{name}-%{version}

%build
export EXTRA_GOFLAGS="-gcflags=\"-N -l\""
export EXTRA_CFLAGS="-O0 -g"
export EXTRA_CDEFINE="-D__x86_64__"

cd %{_builddir}/%{name}-%{version}
%make_build

%install
cd %{_builddir}/%{name}-%{version}
%make_install

%check
cd %{_builddir}/%{name}-%{version}
#make
#make test

%files
%defattr(-,root,root)
%{_bindir}/*

%changelog
* Mon Sep 13 2021 huangliming<huangliming5@huawei.com> - 1.0.0-1
- first package

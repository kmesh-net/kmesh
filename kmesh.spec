Name:          kmesh
Version:       1.0.0
Release:       1
Summary:       %{name} is a eBPF-based service mesh kernel solution
License:       Mulan PSL v2
URL:           https://gitee.com/openeuler
Source0:       %{name}-%{version}.tar.gz

BuildRequires: clang llvm
BuildRequires: libbpf-devel kernel-devel
BuildRequires: golang

Requires: libbpf bpftool

%description
%{name} is a eBPF-based service mesh kernel solution.

ExclusiveArch: x86_64 aarch64

%prep
%autosetup -n %{name}-%{version}

%build
%make_build

%install
%make_install

%check
make test

%files
%defattr(-,root,root)

%changelog
* Mon Sep 13 2021 huangliming<huangliming5@huawei.com> - 1.0.0-1
- first package

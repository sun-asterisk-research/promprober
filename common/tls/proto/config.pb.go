// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.1
// source: github.com/sun-asterisk-research/promprober/common/tls/proto/config.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TLSConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// CA certificate file to verify certificates provided by the other party.
	CaFile *string `protobuf:"bytes,1,opt,name=ca_file,json=caFile" json:"ca_file,omitempty"`
	// Local certificate file.
	CertFile *string `protobuf:"bytes,2,opt,name=cert_file,json=certFile" json:"cert_file,omitempty"`
	// Private key file corresponding to the certificate above.
	KeyFile *string `protobuf:"bytes,3,opt,name=key_file,json=keyFile" json:"key_file,omitempty"`
	// Whether to ignore the cert validation.
	InsecureSkipVerify *bool `protobuf:"varint,4,opt,name=insecure_skip_verify,json=insecureSkipVerify" json:"insecure_skip_verify,omitempty"`
	// ServerName override
	ServerName *string `protobuf:"bytes,5,opt,name=server_name,json=serverName" json:"server_name,omitempty"`
}

func (x *TLSConfig) Reset() {
	*x = TLSConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TLSConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TLSConfig) ProtoMessage() {}

func (x *TLSConfig) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TLSConfig.ProtoReflect.Descriptor instead.
func (*TLSConfig) Descriptor() ([]byte, []int) {
	return file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescGZIP(), []int{0}
}

func (x *TLSConfig) GetCaFile() string {
	if x != nil && x.CaFile != nil {
		return *x.CaFile
	}
	return ""
}

func (x *TLSConfig) GetCertFile() string {
	if x != nil && x.CertFile != nil {
		return *x.CertFile
	}
	return ""
}

func (x *TLSConfig) GetKeyFile() string {
	if x != nil && x.KeyFile != nil {
		return *x.KeyFile
	}
	return ""
}

func (x *TLSConfig) GetInsecureSkipVerify() bool {
	if x != nil && x.InsecureSkipVerify != nil {
		return *x.InsecureSkipVerify
	}
	return false
}

func (x *TLSConfig) GetServerName() string {
	if x != nil && x.ServerName != nil {
		return *x.ServerName
	}
	return ""
}

var File_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto protoreflect.FileDescriptor

var file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDesc = []byte{
	0x0a, 0x49, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x75, 0x6e,
	0x2d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x69, 0x73, 0x6b, 0x2d, 0x72, 0x65, 0x73, 0x65, 0x61, 0x72,
	0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x2f, 0x63, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x70, 0x72, 0x6f,
	0x6d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x74,
	0x6c, 0x73, 0x22, 0xaf, 0x01, 0x0a, 0x09, 0x54, 0x4c, 0x53, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x17, 0x0a, 0x07, 0x63, 0x61, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x63, 0x61, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x65, 0x72,
	0x74, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x65,
	0x72, 0x74, 0x46, 0x69, 0x6c, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x69,
	0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x46, 0x69, 0x6c,
	0x65, 0x12, 0x30, 0x0a, 0x14, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x5f, 0x73, 0x6b,
	0x69, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x12, 0x69, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x53, 0x6b, 0x69, 0x70, 0x56, 0x65, 0x72,
	0x69, 0x66, 0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x4e, 0x61, 0x6d, 0x65, 0x42, 0x3e, 0x5a, 0x3c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x73, 0x75, 0x6e, 0x2d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x69, 0x73, 0x6b, 0x2d,
	0x72, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x2f, 0x70, 0x72, 0x6f, 0x6d, 0x70, 0x72, 0x6f,
	0x62, 0x65, 0x72, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x74, 0x6c, 0x73, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f,
}

var (
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescOnce sync.Once
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescData = file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDesc
)

func file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescGZIP() []byte {
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescOnce.Do(func() {
		file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescData)
	})
	return file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDescData
}

var file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_goTypes = []interface{}{
	(*TLSConfig)(nil), // 0: promprober.common.tls.TLSConfig
}
var file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_init() }
func file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_init() {
	if File_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TLSConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_goTypes,
		DependencyIndexes: file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_depIdxs,
		MessageInfos:      file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_msgTypes,
	}.Build()
	File_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto = out.File
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_rawDesc = nil
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_goTypes = nil
	file_github_com_sun_asterisk_research_promprober_common_tls_proto_config_proto_depIdxs = nil
}

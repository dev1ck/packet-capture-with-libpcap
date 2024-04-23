# Packet Capture 및 분석 도구

libpcap 라이브러리를 이용하여 네트워크 상의 실시간으로 흐르는 패킷을 capture하고, 프로토콜 타입에 맞춰서 파싱한 후 데이터화 하는 command lien 기반의 tool

<aside>
💡 Tcpdump와 유사한 인터페이스로 개발 됐으며, wireshark의 HTTP파싱 기능과 Server의 private key를 이용한 HTTPS 복호화 기능을 구현했습니다.
</aside>

<br/>

## 🛠️ 사용 기술 및 라이브러리

- C++
- OpenSSL, libpcap

<br/>

## 🔗 아키텍처
### Class Diagram
![클래스 다이어그램](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/59c2c672-de35-409d-9b82-1175b97af199)

### Sequence Diagram (전체)
![시퀀스다이어그램 전체](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/eeef9e69-e0ff-4212-a7a9-ebea4271d1b6)

### Sequence Diagram (로딩 및 시작)
![시퀀스다이어그램_setting   start](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/373dd870-fcf6-4e2d-aa44-6ca81093b77a)

### Sequence Diagram (패킷 분류)
![시퀀스다이어그램_분류](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/f44305fa-0c50-4b10-91d2-5cfe96cec11a)

### Sequence Diagram (SSL 파싱)
![시퀀스다이어그램_TCP_Payload](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/0ca619ea-82c4-4f54-9b39-aa155003f949)

### Active Diagram (HTTP 파싱)
![액티브 다이어그램_HTTP](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/ca03c96e-8f51-426f-85f4-bda1b798670f)

<br/>

## ⚡ 기능 및 옵션 소개
### 기능
- 동작 모드: Live capture, Write mode, Read mode
- 지원 프로토콜: ARP, ICMP, TCP, HTTP, HTTPS
- gzip 압축 해제 기능 지원
- HTTP 바이너리 파일 저장 기능

### 옵션
![옵션](https://github.com/dev1ck/packet-capture-with-libpcap/assets/96347313/5e69d5b3-0966-445a-a05c-c3fc79be2025)

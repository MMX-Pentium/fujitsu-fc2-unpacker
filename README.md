# fujitsu-fc2-unpacker

富士通製PCのリカバリディスクに含まれる DataCloningWizard 形式（`DPIMGFHD2` / `.fc2`, `.002`, `.003` ...）の Windows リカバリイメージを解析・検証・アンパックするスクリプトです。

- **外部ライブラリ不要**（Python 3 標準ライブラリのみで動作）
- **ISO 直接読み込み対応**（UDF 1.02 / 1.50 パーサを内蔵しているため、DVD ISO を事前展開せずにそのまま指定可能）
- 展開済みの `.fc2` / `.002` / `.003` ファイルの直接指定にも対応

## 動作要件

- Python 3.8 以上

## 使い方

### 1. イメージ情報の表示 (`info`)

ヘッダ・パーティション構成・分割ボリューム一覧・付属の `.inf` / `.fj` / `.crc` 情報を表示します。

```bash
python3 unpack_fc2.py info "リカバリディスク1.iso" "リカバリディスク2.iso"
```

### 2. イメージ整合性・CRC32 検証 (`verify`)

全圧縮チャンクの展開整合性を確認し、同梱の `.crc` マニフェストが存在する場合は全ファイルのサイズおよび CRC32 を照合します。

```bash
python3 unpack_fc2.py verify "リカバリディスク1.iso" "リカバリディスク2.iso"
```

### 3. RAW NTFS パーティションイメージの復元 (`unpack-img`)

スパース形式の RAW NTFS パーティションイメージ（`mount -o loop,ro` や `7z` 等で参照可能）を再構築します。

```bash
# NTFS パーティションイメージとして復元
python3 unpack_fc2.py unpack-img "リカバリディスク1.iso" "リカバリディスク2.iso" -o ./partition.img

# MBR + Track 0 込みの完全ディスクイメージとして復元
python3 unpack_fc2.py unpack-img "リカバリディスク1.iso" "リカバリディスク2.iso" -o ./disk.img --full-disk
```

### 4. ファイルの直接展開 (`extract`)

RAW イメージを作成せず、ディレクトリツリーへ直接ファイルを展開します。

```bash
# 全ファイルを展開（--verify-crc で .crc 照合付き）
python3 unpack_fc2.py extract "リカバリディスク1.iso" "リカバリディスク2.iso" -o ./extracted --verify-crc

# 特定パスのみ部分展開（大文字小文字区別なし）
python3 unpack_fc2.py extract "リカバリディスク1.iso" "リカバリディスク2.iso" -o ./extracted --filter '\Fujitsu\*'
```

## 補足

- 展開済みファイルを使う場合は `.fc2` のみ指定すれば同一ディレクトリ内の `.002`, `.003`, `.inf`, `.crc` 等を自動検出します。
- 現在の対応対象は `DPIMGFHD2`（32bitセクタ版）の NTFS 論理バックアップイメージです。

/*
 *
 *
 *
 * '00' || BT || PS || X'00' D where:
 *
 *
 */

map<string, bytearray> asin_values = {
    {"sha1", hex::decode("3021300906052b0e03021a05000414")}};
bytearray create_block(const string& message, const int block_size = 64) {
  bytearray hash_value = sha1(message);
  bytearray D = asin_values["sha1"] + hash_value;

  bytearray BT(1, 0x01);
  bytearray PS(max(0, block_size - static_cast<int>(D.size()) - 3), 0xff);

  bytearray format(1, 0x00);
  format = format + BT + PS + bytearray(1, 0x00) + D;

  return format;
}

bigint create_fake_block(const string& message) {
  string fake_block = "0001ff003021300906052b0e03021a05000414" +
                      hex::encode(sha1(message).to_str());
  // fake_block = fake_block + string(128UL - fake_block.size(), '0');
  fake_block = fake_block + string(4, '0');

  bigint s("0x" + fake_block);

  cout << std::hex << s << endl;

  // auto status = cbrt_close(s);
  // if (!status.second ) {
  //  s = s + (cube(status.first) - s);
  //}
  //
  //
  for (bigint i("0x0"); i < bigint("0xffff"); ++i) {
    if (i % 5000 == 0) {
      cout << "i = " << i << endl;
    }

    bigint c = s + i;
    if (cbrt(c) != 0) {
      cout << "c = " << c << endl;
      break;
    }
  }

  // cout << std::hex << cube(status.first) << endl;

  return status.first;
}

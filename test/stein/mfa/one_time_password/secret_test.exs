defmodule Stein.MFA.OneTimePassword.SecretTest do
  use ExUnit.Case

  alias Stein.MFA.OneTimePassword.Secret

  @example_label "bob@smartlogic.io"
  @example_issuer "SmartLogic"

  defp generic_hotp(_context) do
    {:ok, hotp: Secret.new_hotp(@example_label, issuer: @example_issuer)}
  end

  defp generic_totp(_context) do
    {:ok, totp: Secret.new_totp(@example_label, issuer: @example_issuer)}
  end

  defp hotp_with_issuer(_context) do
    {:ok, hotp: Secret.new_hotp(@example_label, issuer: @example_issuer)}
  end

  defp totp_with_issuer(_context) do
    {:ok, totp: Secret.new_totp(@example_label, issuer: @example_issuer)}
  end

  describe "general creation" do
    setup [:generic_totp, :generic_hotp]

    test "label included", c do
      assert c[:hotp].label == @example_label
      assert c[:totp].label == @example_label
    end

    test "has expected default algorithm (SHA1)", c do
      assert c[:hotp].algorithm == :SHA1
      assert c[:totp].algorithm == :SHA1
    end

    test "algorithm is overrideable" do
      assert Secret.new_hotp(@example_label, algorithm: :SHA256).algorithm == :SHA256
      assert Secret.new_totp(@example_label, algorithm: :SHA256).algorithm == :SHA256
    end

    test "has expected default digits (6)", c do
      assert c[:hotp].digits == 6
      assert c[:totp].digits == 6
    end
  end

  describe "general creation with issuer" do
    setup [:hotp_with_issuer, :totp_with_issuer]

    test "issuer included if specified", c do
      assert c[:hotp].issuer == @example_issuer
      assert c[:totp].issuer == @example_issuer
    end
  end

  describe "secret (K) creation" do
    setup [:generic_totp, :generic_hotp]

    test "secret is valid base32", c do
      assert c[:hotp].secret_value |> :pot_base32.decode()
      assert c[:totp].secret_value |> :pot_base32.decode()
    end

    test "secret has expected default bits (160)", c do
      assert (c[:hotp].secret_value |> :pot_base32.decode() |> byte_size) * 8 == 160
      assert (c[:totp].secret_value |> :pot_base32.decode() |> byte_size) * 8 == 160
    end

    test "secret bitlength is overrideable" do
      assert (Secret.new_hotp(@example_label, bits: 256).secret_value
              |> :pot_base32.decode()
              |> byte_size) * 8 == 256

      assert (Secret.new_totp(@example_label, bits: 256).secret_value
              |> :pot_base32.decode()
              |> byte_size) * 8 == 256
    end
  end

  describe "totp creation" do
    setup [:generic_totp]

    test("type is correct", c, do: assert(c[:totp].type == :totp))

    test("period is included", c, do: assert(!is_nil(c[:totp].period)))

    test("period has expected default", c, do: assert(c[:totp].period == 30))

    test "period is overrideable",
      do: assert(Secret.new_totp(@example_label, period: 50).period == 50)
  end

  describe "hotp creation" do
    setup [:generic_hotp]

    test("type is correct", c, do: assert(c[:hotp].type == :hotp))

    test("counter is included", c, do: assert(!is_nil(c[:hotp].counter)))

    test("counter has expected default", c, do: assert(c[:hotp].counter == 0))

    test "counter is overrideable",
      do: assert(Secret.new_hotp(@example_label, initial_counter: 20).counter == 20)
  end

  # describe "enrollment url generation (generic)" do
  #   setup [:generic_totp, :generic_hotp]

  #   test "scheme is otpauth", c do
  #     assert URI.parse(c[:])
  # end
end

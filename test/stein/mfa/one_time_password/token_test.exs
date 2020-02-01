defmodule Stein.MFA.OneTimePassword.TokenTest do
  use ExUnit.Case

  alias Stein.MFA.OneTimePassword.{Secret, Token}

  @example_label "bob@smartlogic.io"

  defp generic_hotp_secret(_context) do
    {:ok, hotp_secret: Secret.new_hotp(@example_label)}
  end

  defp generic_totp_secret(_context) do
    {:ok, totp_secret: Secret.new_totp(@example_label)}
  end

  describe "HMAC based token" do
    setup [:generic_hotp_secret]

    test "is well formed", c do
      token_value = Token.generate(c[:hotp_secret]).value

      assert Integer.parse(token_value)
      assert String.length(token_value) == c[:hotp_secret].digits
    end

    test "validates", c do
      token = Token.generate(c[:hotp_secret])

      assert Token.validate(token)
    end

    test "validates when chained", c do
      s0 = c[:hotp_secret]
      t0 = Token.generate(s0)

      assert Token.validate(t0)

      s1 = t0.secret
      t1 = Token.generate(s1)

      assert Token.validate(t1)

      s2 = t1.secret
      t2 = Token.generate(s2)

      assert Token.validate(t2)

      s3 = t2.secret
      t3 = Token.generate(s3)

      assert Token.validate(t3)

      # ad nauseam, possibly with an edge at overflow
    end
  end

  # Time based tokens being, you know, time-based we kinda have to have
  # some tests with sleeps in them. For minimum pain, I've reduced the
  # time period involved to the minimum of 1 second. But if you are
  # possesed with some desire to test a longer time-scale, this is your guy
  @time_based_test_period 1

  describe "Time based token" do
    setup [:generic_totp_secret]

    test "is well formed", c do
      token_value = Token.generate(c[:totp_secret]).value

      assert Integer.parse(token_value)
      assert String.length(token_value) == c[:totp_secret].digits
    end

    test "validates immediately", c do
      token = Token.generate(c[:totp_secret])

      assert Token.validate(token)
    end

    test "validates within period, doesn't after period" do
      secret = Secret.new_totp(@example_label, period: @time_based_test_period)
      token = Token.generate(secret)

      Process.sleep(@time_based_test_period * 300)
      assert Token.validate(token)

      Process.sleep(@time_based_test_period * 1001)
      refute Token.validate(token)
    end

     test "validates within period + period*time_tolerance, doesn't after period" do
      secret = Secret.new_totp(@example_label, period: @time_based_test_period)
      token = Token.generate(secret)

      assert Token.validate(token, 1)

      Process.sleep(@time_based_test_period * 1000)
      assert Token.validate(token, 1)

      Process.sleep(@time_based_test_period * 1001)
      refute Token.validate(token, 1)
    end
  end
end

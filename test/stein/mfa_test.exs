defmodule Stein.MFATest do
  use ExUnit.Case

  #doctest Stein.MFA

  alias Stein.MFA

  test "greets the world" do
    assert MFA.hello() == :world
  end
end

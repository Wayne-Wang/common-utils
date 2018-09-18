package com.wayne.exception;

/**
 * 基础异常
 * @Author Wayne.Wang
 * @Date 18/9/18
 */
public class BaseException extends RuntimeException {


    public BaseException() {
        super();
    }

    public BaseException(String message) {
        super(message);
    }
}

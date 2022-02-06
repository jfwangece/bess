#include "regression.h"

template <class T>
bool LinearRegression<T>::Train() {
  if (x_.size() < 2) {
    return false;
  }

  T sum_x = 0, sum_x2 = 0, sum_y = 0, sum_xy = 0;
  int n = x_.size();
  for (int i = 0; i < n; i++) {
    sum_x += x_[i];
    sum_x2 += x_[i] * x_[i];
    sum_y += y_[i];
    sum_xy += x_[i] * y_[i];
  }

  base_x_ = x_[0];
  base_y_ = y_[0];
  slope_ = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
  // double a = (sum_y - b * sum_x) / n;
  return true;
}

template <class T>
inline T LinearRegression<T>::GetY(T x) {
  return base_y_ + (x - base_x_) * slope_;
}

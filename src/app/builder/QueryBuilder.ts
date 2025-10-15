import { FilterQuery, Query } from 'mongoose';

class QueryBuilder<T> {
  public modelQuery: Query<T[], T>;
  public query: Record<string, unknown>;
  constructor(modelQuery: Query<T[], T>, query: Record<string, unknown>) {
    this.modelQuery = modelQuery;
    this.query = query;
  }
  search(searchableFields: string[]) {
    const search = this?.query?.search as string;

    if (search) {
      this.modelQuery = this.modelQuery.find({
        $or: searchableFields.map(
          (field) =>
            ({
              [field]: { $regex: search, $options: 'i' },
            }) as FilterQuery<T>,
        ),
      });
    }
    return this;
  }
  filter() {
    const queryObj = { ...this.query };
    const excludeField = ['search', 'sortOrder', 'sortBy'];
    excludeField.forEach((key) => delete queryObj[key]);

    // searchQuery = searchQuery.find({ author: queryObj?.filter });
    // console.log(queryObj);
    if (Object.keys(queryObj).length === 0) {
      return this;
    }

    this.modelQuery = this.modelQuery.find({ author: queryObj.filter });
    return this;
  }
  sort() {
    const sortBy = this.query?.sortBy as string;
    const sortOrder = this.query?.sortOrder as string;
    let sortStr = '';
    if (sortBy && sortOrder) {
      sortStr = `${sortOrder === 'desc' ? '-' : ''}${sortBy}`;
      this.modelQuery = this.modelQuery.sort(sortStr);
    }
    return this;
  }
}

export default QueryBuilder;
